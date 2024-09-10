from http import client
import tkinter as tk
from tkinter import scrolledtext
import paho.mqtt.client as mqtt
import numpy as np
import random
import threading
from scipy.signal import convolve

# Datos del broker
broker = "test.mosquitto.org"
port = 1883
topico_publicar = "topico/wpp2"
topico_suscribir = "topico/wpp2"

# Identificador único para el remitente
id_usuario = random.randint(1000, 9999)  # Un identificador único para este cliente


# Parámetros para la simulación de sincronización
periodo_sinc = 100  # Define el período para la señal sinc (puedes ajustar este valor)
sincronizado = True  # Controla si la comunicación está sincronizada o desincronizada

# FUNCIONES
def binario_a_hexadecimal(binario):
    """Convierte una cadena binaria en formato hexadecimal"""
    hex_value = hex(int(binario, 2))[2:]  # Convierte binario a hexadecimal
    return hex_value.upper().zfill(len(binario) // 4)  # Completa con ceros a la izquierda si es necesario

def binario_a_ascii(binario):
    """Convierte una cadena binaria en formato ASCII"""
    ascii_text = ''.join(chr(int(binario[i:i+8], 2)) for i in range(0, len(binario), 8))
    return ascii_text

def mensaje_a_stomp(mensaje):
    # Codificar el mensaje en texto, con un formato de STOMP predecible
    stomp_message = f"SEND\ndestination:/queue/test:\n\n-STOMP{mensaje}\x00"
    print(f"Mensaje STOMP generado: {stomp_message}")
    return stomp_message



def sinc_filter(length, alpha):
    t = np.arange(-length // 2, length // 2 + 1)
    return np.sinc(t / alpha)

def pam4_encode(mensaje_binario):
   # print(f"Mensaje_binario: {mensaje_binario}")
    pam4_signal = []
    for i in range(0, len(mensaje_binario), 2):
        bits = mensaje_binario[i:i+2]
        if bits == '00':
            pam4_signal.append(-3)  # Nivel -3
        elif bits == '01':
            pam4_signal.append(-1)  # Nivel -1
        elif bits == '10':
            pam4_signal.append(1)   # Nivel 1
        elif bits == '11':
            pam4_signal.append(3)   # Nivel 3
    return np.array(pam4_signal)

def generar_ruido(signal_length, intensidad):
    ruido = np.random.normal(0, intensidad, signal_length)
    return ruido

def pam4_decode(pam4_signal):
    niveles_pam4 = np.array([-3, -1, 1, 3])
    pam4_signal = np.array([niveles_pam4[np.argmin(np.abs(niveles_pam4 - val))] for val in pam4_signal])

    binario = ''
    for value in pam4_signal:
        if value == -3:
            binario += '00'
        elif value == -1:
            binario += '01'
        elif value == 1:
            binario += '10'
        elif value == 3:
            binario += '11'
    return binario


#Funciones de encapsulación y desincronizacion

def generar_mensaje(mensaje):
    # Capa de Aplicación (STOMP)
    stomp_message = mensaje_a_stomp(mensaje)
    print(f"Mensaje STOMP: {stomp_message}")

    # Incluir el ID del usuario en el mensaje para identificar quién lo envía
    mensaje_con_id = f"{id_usuario}:{stomp_message}"
    print(f"Mensaje con id: {mensaje_con_id}")

    # Convertir el mensaje con ID a bytes (UTF-8) para su encapsulación en TCP
    mensaje_con_id_bytes = mensaje_con_id.encode('utf-8')

    print(f"mensaje_con_id_bytes: {mensaje_con_id_bytes}")

    # Capa de Transporte (TCP)
    tcp_message = encapsular_tcp(mensaje_con_id_bytes)
    
    # Capa de Red (IP)
    ip_message = encapsular_ip(tcp_message)

    # Devuelve el mensaje encapsulado en IP
    return ip_message

def encapsular_tcp(payload):
    # Modificar el encabezado TCP y agregar una codificación binaria diferente para TCP
    tcp_header = b''

    # Puertos inventados
    puerto_origen = 12345
    puerto_destino = 80
    tcp_header += puerto_origen.to_bytes(2, 'big')
    tcp_header += puerto_destino.to_bytes(2, 'big')

    # Números de secuencia y confirmación aleatorios
    numero_secuencia = random.randint(10000, 20000)
    numero_confirmacion = 500
    tcp_header += numero_secuencia.to_bytes(4, 'big')
    tcp_header += numero_confirmacion.to_bytes(4, 'big')

    # Longitud del encabezado y flags
    longitud_cabecera = (5 << 4)
    flags = 0x18
    tcp_header += longitud_cabecera.to_bytes(1, 'big')
    tcp_header += flags.to_bytes(1, 'big')

    # Tamaño de ventana y checksum
    ventana = 65535
    checksum = 0
    tcp_header += ventana.to_bytes(2, 'big')
    tcp_header += checksum.to_bytes(2, 'big')
    tcp_header += b'\x00\x00'  # Puntero urgente en 0

    # Codificar el payload TCP de forma única
    tcp_payload_binario = ''.join(format(byte, '08b') for byte in payload)
    
    print(f"Encabezado TCP: {tcp_header}")
    print(f"tcp_header + payload: {tcp_header + payload}")


    return tcp_header + payload  # Aquí payload en binario


def encapsular_ip(payload):
    # Función para encapsular en IP
    
    # Encabezado IP fijo con valores inventados y fijos
    ip_header = b''

    # Versión (IPv4) y longitud del encabezado (20 bytes mínimo)
    version = 4  # IPv4
    longitud_cabecera = 5  # 20 bytes (en palabras de 32 bits)
    ip_header += ((version << 4) + longitud_cabecera).to_bytes(1, 'big')

    # Tipo de servicio (8 bits) - valor fijo (sin importancia en este contexto)
    tipo_servicio = 0
    ip_header += tipo_servicio.to_bytes(1, 'big')

    # Longitud total del paquete (16 bits) - encabezado IP (20 bytes) + longitud del payload
    longitud_total = 20 + len(payload)  # 20 bytes de cabecera + longitud del payload
    ip_header += longitud_total.to_bytes(2, 'big')

    # Identificación del paquete (16 bits) - valor fijo inventado
    identificacion = 54321
    ip_header += identificacion.to_bytes(2, 'big')

    # Flags (3 bits) y desplazamiento de fragmento (13 bits) - sin fragmentación
    flags_y_fragment_offset = 0
    ip_header += flags_y_fragment_offset.to_bytes(2, 'big')

    # Tiempo de vida (TTL, 8 bits) - inventado
    ttl = 64  # Tiempo de vida
    ip_header += ttl.to_bytes(1, 'big')

    # Protocolo (8 bits) - TCP es 6
    protocolo = 6  # TCP
    ip_header += protocolo.to_bytes(1, 'big')

    # Checksum del encabezado IP (16 bits) - se deja como 0 (no se calcula)
    checksum_ip = 0
    ip_header += checksum_ip.to_bytes(2, 'big')

    # Direcciones IP de origen y destino (32 bits cada una) - inventadas y fijas
    ip_origen = '192.168.0.1'  # IP origen inventada
    ip_destino = '192.168.0.2'  # IP destino inventada
    ip_header += bytes(map(int, ip_origen.split('.')))  # Convertir la IP origen a bytes
    ip_header += bytes(map(int, ip_destino.split('.')))  # Convertir la IP destino a bytes

    # Devuelve el encabezado IP combinado con el payload
    return ip_header + payload

def generar_encabezado_ethernet():
    mac_origen = random.randint(0, 2**48-1)  # MAC origen aleatoria
    mac_destino = random.randint(0, 2**48-1)  # MAC destino aleatoria
    tipo_ethernet = '0800'  # Tipo IPv4 en hexadecimal
    
    # Convertir las direcciones MAC a formato binario de 48 bits
    mac_origen_bin = format(mac_origen, '048b')
    mac_destino_bin = format(mac_destino, '048b')
    
    # Tipo de Ethernet en binario
    tipo_ethernet_bin = format(int(tipo_ethernet, 16), '016b')
    
    # Encabezado Ethernet completo en binario
    encabezado_ethernet_bin = mac_destino_bin + mac_origen_bin + tipo_ethernet_bin
    
    print(f"Encabezado Ethernet binario: {encabezado_ethernet_bin}")  # Verifica que se genere correctamente
    
    return encabezado_ethernet_bin  # Devolver binario

def aplicar_desincronizacion(signal, periodo):
    desincronizado_signal = np.roll(signal, shift=periodo)
    return desincronizado_signal

#Funciones para conectar al MQTT y enviar mensaje

def iniciar_mqtt():
    try:
        client.connect(broker, port, 60)  # Conectar al broker MQTT
        client.loop_start()  # Iniciar el bucle del cliente MQTT para procesar mensajes
    except Exception as e:
        print(f"Error al conectar al broker MQTT: {e}")

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("Conectado al broker con éxito")
        client.subscribe(topico_suscribir)
    else:
        print(f"Error al conectar, código {rc}")

def on_message(client, userdata, msg):
    # Recibir el mensaje como una lista de bits o flotantes
    mensaje_bits = msg.payload.decode()

    # Convertir el mensaje recibido en un array de números flotantes
    try:
        convolucionada = np.fromstring(mensaje_bits.strip('[]'), dtype=float, sep=',')
    except ValueError as e:
        print(f"Error en la conversión del mensaje: {e}")
        return

    # Aplicar filtro sinc
    filter_length = 100
    alpha = 0.25
    sinc_filter_kernel = sinc_filter(filter_length, alpha)

    # Si la comunicación está sincronizada o no
    if sincronizado:
        reversed_signal = convolve(convolucionada, sinc_filter_kernel, mode='same')
    else:
        desincronizacion_periodo = periodo_sinc
        desincronizada_signal = aplicar_desincronizacion(convolucionada, desincronizacion_periodo)
        reversed_signal = convolve(desincronizada_signal, sinc_filter_kernel, mode='same')

    # Redondear y decodificar la señal PAM4
    pam4_signal = np.round(reversed_signal).astype(int)
    ethernet_message_bin = pam4_decode(pam4_signal)
    print(f"Mensaje ethernet binario: {ethernet_message_bin}")

    # Decodificar Ethernet
    try:
        ethernet_encabezado = decodificar_encabezado_ethernet(ethernet_message_bin)
        print(f"Encabezado ethernet: {ethernet_encabezado}")
        ip_message_bin = ethernet_encabezado['payload']
        print(f"Mensaje IP binario: {ip_message_bin}")
    except ValueError as e:
        print(f"Error desencapsulando Ethernet: {e}")
        return

    # Decodificar IP
    try:
        ip_encabezado = decodificar_encabezado_ip(ip_message_bin)
        print(f"Encabezado IP: {ip_encabezado}")
        tcp_message_bin = ip_encabezado['payload']
        print(f"Mensaje TCP binario: {tcp_message_bin}")
    except ValueError as e:
        print(f"Error desencapsulando IP: {e}")
        return

    # Decodificar TCP
    try:
        tcp_encabezado = decodificar_encabezado_tcp(tcp_message_bin)
        print(f"Encabezado TCP: {tcp_encabezado}")
        stomp_message_bin = tcp_encabezado['payload']
        print(f"Mensaje STOMP binario: {stomp_message_bin}")
    except ValueError as e:
        print(f"Error desencapsulando TCP: {e}")
        return

    # Decodificar STOMP
    try:
        stomp_mensaje = decodificar_stomp(stomp_message_bin)
        print(f"Mensaje STOMP: {stomp_mensaje}")
        id_remitente , mensaje_recibido = stomp_mensaje.split('SEND\ndestination:/queue/test:\n\n-STOMP' , 1)
        print(f"ID de remitente: {id_remitente}")
        print(f"Mensaje recibido: {mensaje_recibido}")
    except ValueError as e:
        print(f"Error desencapsulando STOMP: {e}")
        return

    # Si el mensaje proviene de este cliente, ignorarlo
    print(f"Id_usuario en string: {str(id_usuario)}")
    print(f"Id_remitente: {id_remitente}")
    if int(id_remitente[20:24]) == id_usuario:
        print(f"Mensaje propio recibido, se ignora: {mensaje_recibido}")
    else:
        # Si el mensaje es de otro cliente, mostrarlo
        texto_mensajes.insert(tk.END, f"Recibido: {mensaje_recibido}\n", 'received\n')
        texto_mensajes.insert(tk.END, f"")
        texto_mensajes.yview(tk.END)

# Funciones para desencapsular cada protocolo

def decodificar_encabezado_ethernet(mensaje_binario):
    # Toma los primeros 14 bytes del mensaje binario para extraer el encabezado Ethernet
    mac_destino_bin = mensaje_binario[0:48]
    mac_origen_bin = mensaje_binario[48:96]
    tipo_protocolo = mensaje_binario[96:112]  # El tipo de protocolo debería ser IP (0x0800 para IPv4)
    payload = mensaje_binario[112:]
    
    # Convertir MAC y tipo de protocolo a formato legible
    mac_destino = ':'.join(f'{int(mac_destino_bin[i:i+8], 2):02X}' for i in range(0, 48, 8))
    mac_origen = ':'.join(f'{int(mac_origen_bin[i:i+8], 2):02X}' for i in range(0, 48, 8))
    tipo_protocolo_hex = f'{int(tipo_protocolo, 2):04X}'

    return {'mac_destino': mac_destino, 'mac_origen': mac_origen, 'tipo_protocolo': tipo_protocolo_hex, 'payload': payload}

def decodificar_encabezado_ip(mensaje_binario):
    # Extraer la longitud del encabezado IP y verificar el tipo de protocolo (TCP es 6)
    ip_header_length = int(mensaje_binario[0:4], 2) * 4  # En palabras de 32 bits
    protocolo = int(mensaje_binario[72:80], 2)  # El protocolo (debería ser TCP)
    payload = mensaje_binario[ip_header_length*8:]  # Tomamos el payload a partir del fin del encabezado IP
    
    # Convertir la dirección IP de formato binario a formato decimal
    ip_origen = '.'.join(str(int(mensaje_binario[i:i+8], 2)) for i in range(0, 32, 8))
    ip_destino = '.'.join(str(int(mensaje_binario[i:i+8], 2)) for i in range(32, 64, 8))
    
    return {'ip_origen': ip_origen, 'ip_destino': ip_destino, 'protocolo': protocolo, 'payload': payload}

def decodificar_encabezado_tcp(mensaje_binario):
    # Asegúrate de que el mensaje binario tiene al menos el tamaño mínimo para un encabezado TCP (20 bytes = 160 bits)
    if len(mensaje_binario) < 160:
        raise ValueError("El mensaje TCP es demasiado corto para contener un encabezado TCP válido.")
    
    # Extraer los primeros 20 bytes (160 bits) para el encabezado TCP
    puerto_origen = int(mensaje_binario[0:16], 2)
    puerto_destino = int(mensaje_binario[16:32], 2)
    numero_secuencia = int(mensaje_binario[32:64], 2)
    numero_confirmacion = int(mensaje_binario[64:96], 2)
    longitud_cabecera = int(mensaje_binario[96:100], 2) * 4 # En palabras de 32 bits
    flags = mensaje_binario[100:106]
    ventana = int(mensaje_binario[112:128], 2)



    if longitud_cabecera == 0 or longitud_cabecera < 5:
        longitud_cabecera = 4  # El valor mínimo en palabras de 32 bits
    
    
    
    print(f"longitud_cabecera: {longitud_cabecera}")
    # Obtener el payload (datos de la capa de aplicación), que comienza después del encabezado TCP
    payload = mensaje_binario[longitud_cabecera * 8:]  # Tomamos el payload después del fin del encabezado
    
    # Convertir flags a formato legible
    flags_str = f"{int(flags, 2):06b}"
    
    return {
        'puerto_origen': puerto_origen, 'puerto_destino': puerto_destino,
        'numero_secuencia': numero_secuencia, 'numero_confirmacion': numero_confirmacion,
        'longitud_cabecera': longitud_cabecera, 'flags': flags_str, 'ventana': ventana,
        'payload': payload
    }

def imprimir_datos_decodificados(mensaje_binario):
    # Decodificar Ethernet
    ethernet_encabezado = decodificar_encabezado_ethernet(mensaje_binario)
    print(f"Dirección MAC de destino: {ethernet_encabezado['mac_destino']}")
    print(f"Dirección MAC de origen: {ethernet_encabezado['mac_origen']}")
    print(f"Tipo de protocolo: {ethernet_encabezado['tipo_protocolo']}")

    # Decodificar IP
    ip_message_bin = ethernet_encabezado['payload']
    ip_encabezado = decodificar_encabezado_ip(ip_message_bin)
    print(f"IP de origen: {ip_encabezado['ip_origen']}")
    print(f"IP de destino: {ip_encabezado['ip_destino']}")
    print(f"Protocolo: {ip_encabezado['protocolo']}")

    # Decodificar TCP
    tcp_message_bin = ip_encabezado['payload']
    tcp_encabezado = decodificar_encabezado_tcp(tcp_message_bin)
    print(f"Puerto de origen: {tcp_encabezado['puerto_origen']}")
    print(f"Puerto de destino: {tcp_encabezado['puerto_destino']}")
    print(f"Número de secuencia: {tcp_encabezado['numero_secuencia']}")
    print(f"Número de confirmación: {tcp_encabezado['numero_confirmacion']}")
    print(f"Longitud del encabezado TCP: {tcp_encabezado['longitud_cabecera']} bytes")
    print(f"Flags TCP: {tcp_encabezado['flags']}")
    print(f"Tamaño de ventana TCP: {tcp_encabezado['ventana']}")

    # Asegúrate de que el mensaje binario tiene al menos el tamaño mínimo para un encabezado TCP (20 bytes = 160 bits)
    if len(mensaje_binario) < 160:
        raise ValueError("El mensaje TCP es demasiado corto para contener un encabezado TCP válido.")
    
    # Extraer los primeros 20 bytes (160 bits) para el encabezado TCP
    try:
        puerto_origen = mensaje_binario[0:16]  # Primeros 16 bits (puerto de origen)
        puerto_destino = mensaje_binario[16:32]  # Siguientes 16 bits (puerto de destino)
        numero_secuencia = mensaje_binario[32:64]  # Siguientes 32 bits (número de secuencia)
        numero_confirmacion = mensaje_binario[64:96]  # Siguientes 32 bits (número de confirmación)
        longitud_cabecera = len(mensaje_binario[96:100] * 4)  # Siguientes 4 bits (longitud de cabecera en palabras de 32 bits)
        flags = mensaje_binario[100:106]  # Siguientes 6 bits (flags)
        ventana = mensaje_binario[112:128]  # Siguientes 16 bits (ventana)

        # Convertir campos TCP a hexadecimal y ASCII
        puerto_origen_hex = binario_a_hexadecimal(puerto_origen)
        puerto_destino_hex = binario_a_hexadecimal(puerto_destino)
        numero_secuencia_hex = binario_a_hexadecimal(numero_secuencia)
        numero_confirmacion_hex = binario_a_hexadecimal(numero_confirmacion)
        flags_hex = binario_a_hexadecimal(flags)
        ventana_hex = binario_a_hexadecimal(ventana)
        
        print(f"Puerto origen (Hex): {puerto_origen_hex}")
        print(f"Puerto destino (Hex): {puerto_destino_hex}")
        print(f"Número de secuencia (Hex): {numero_secuencia_hex}")
        print(f"Número de confirmación (Hex): {numero_confirmacion_hex}")
        print(f"Flags (Hex): {flags_hex}")
        print(f"Ventana (Hex): {ventana_hex}")
        
        # Obtener el payload (datos de la capa de aplicación), que comienza después del encabezado TCP
        payload = mensaje_binario[longitud_cabecera * 8:]  # Tomamos el payload después del fin del encabezado

        return {'puerto_origen': puerto_origen, 'puerto_destino': puerto_destino,
                'numero_secuencia': numero_secuencia, 'numero_confirmacion': numero_confirmacion,
                'longitud_cabecera': longitud_cabecera, 'flags': flags, 'ventana': ventana,
                'payload': payload}
    
    except Exception as e:
        raise ValueError(f"Error desencapsulando TCP: {e}")

def decodificar_stomp(mensaje_binario):
    # Verificar que la longitud del mensaje binario sea múltiplo de 8
    if len(mensaje_binario) % 8 != 0:
        raise ValueError("La longitud del mensaje binario no es múltiplo de 8. No es un mensaje binario válido para decodificación.")
    
    try:
        # Convertir el mensaje binario en texto (caracteres ASCII)
        mensaje_stomp = ''.join(chr(int(mensaje_binario[i:i+8], 2)) for i in range(0, len(mensaje_binario), 8))
        print(f"Mensaje STOMP decodificado: {mensaje_stomp}")
        
        return mensaje_stomp
    except ValueError as e:
        raise ValueError(f"Error decodificando STOMP: {e}")




#Funcion para enviar mensaje

def enviar_mensaje(event=None):
    mensaje = entrada_mensaje.get()
    
    if mensaje != '':
        # Mostrar solo el mensaje enviado en la interfaz
        texto_mensajes.insert(tk.END, f"Tú: {mensaje}\n", 'sent')  
        texto_mensajes.yview(tk.END)

        # Encapsulación IP
        ip_message = generar_mensaje(mensaje)
        print(f"Mensaje IP completo: {ip_message}")

        # Encapsulación Ethernet (añadiendo encabezado Ethernet)
        encabezado_ethernet = generar_encabezado_ethernet()

        #print(f"Encabezado ethernet sin transformar: {encabezado_ethernet}")

        #Convertir a binario el ip_message
        ip_message_binary = ''.join(format(byte, '08b') for byte in ip_message)

        # Convertir encabezado_ethernet a bytes antes de concatenar
        encabezado_ethernet_bytes = bytes(int(encabezado_ethernet[i:i+8], 2) for i in range(0, len(encabezado_ethernet), 8))
        
        encabezado_ethernet_binary = ''.join(format(byte, '08b') for byte in encabezado_ethernet_bytes)
        

        # Concatenar el encabezado Ethernet con el mensaje IP
        ethernet_message_bin = encabezado_ethernet_binary + ip_message_binary

    
        print(f"Mensaje Ethernet: {ethernet_message_bin}")

        # Asegúrate de que el mensaje Ethernet no está vacío antes de pasar a PAM4
        if not ethernet_message_bin:
            print("Error: El mensaje Ethernet está vacío.")
            return

        # Codificación PAM4
        pam4_signal = pam4_encode(ethernet_message_bin)

        filter_length = 100
        alpha = 0.25
        sinc_filter_kernel = sinc_filter(filter_length, alpha)
        print(f"Pam singal: {pam4_signal}")
        filtered_signal = convolve(pam4_signal, sinc_filter_kernel, mode='same')
        
        # Añadir ruido a la señal
        ruido_intensidad = 0.10
        ruido = generar_ruido(len(filtered_signal), ruido_intensidad)
        signal_con_ruido = filtered_signal + ruido

        print("Señal que se está transmitiendo:", signal_con_ruido.tolist())

        # Publicar el mensaje al broker MQTT
        client.publish(topico_publicar, str(signal_con_ruido.tolist()))
        entrada_mensaje.delete(0, tk.END)


# Interfaz gráfica
ventana = tk.Tk()
ventana.title("Cliente MQTT - Dispositivo 2")
ventana.geometry("600x400")
ventana.configure(bg='#2e2e2e')  # Fondo oscuro

# Marco para los mensajes
frame_mensajes = tk.Frame(ventana, bg='#2e2e2e', bd=2, relief=tk.RAISED)
frame_mensajes.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

texto_mensajes = scrolledtext.ScrolledText(frame_mensajes, width=70, height=15, bg='#1e1e1e', fg='#ffffff', wrap=tk.WORD, font=('Arial', 12))
texto_mensajes.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
texto_mensajes.tag_configure('sent', justify='right', background='#2196F3', foreground='#ffffff', font=('Arial', 12), spacing3=10)
texto_mensajes.tag_configure('received', justify='left', background='#388E3C', foreground='#ffffff', font=('Arial', 12), spacing3=10)

# Marco para la entrada y el botón
frame_input = tk.Frame(ventana, bg='#2e2e2e')
frame_input.pack(padx=10, pady=(0, 10), fill=tk.X)

entrada_mensaje = tk.Entry(frame_input, width=50, font=('Arial', 12), bg='#1e1e1e', fg='#ffffff', borderwidth=2, relief=tk.SUNKEN)
entrada_mensaje.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)

# Crear un botón para enviar mensajes
boton_enviar = tk.Button(frame_input, text="Enviar", command=enviar_mensaje, font=('Arial', 12), bg='#4CAF50', fg='white', relief=tk.RAISED, bd=2)
boton_enviar.pack(side=tk.RIGHT, padx=5, pady=5)

def alternar_sincronizacion():
    global sincronizado
    sincronizado = not sincronizado
    estado = "sincronizado" if sincronizado else "desincronizado"
    texto_mensajes.insert(tk.END, f"Comunicación {estado}\n", 'sent')
    texto_mensajes.yview(tk.END)

boton_alternar_sincronizacion = tk.Button(ventana, text="Alternar Sincronización", command=alternar_sincronizacion, font=('Arial', 12), bg='#FFC107', fg='black', relief=tk.RAISED, bd=2)
boton_alternar_sincronizacion.pack(pady=5)

ventana.bind("<Return>", enviar_mensaje)

# Conectar al broker MQTT
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message


iniciar_mqtt()

ventana.mainloop()