import tkinter as tk
from tkinter import scrolledtext
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import numpy as np
import paho.mqtt.client as mqtt
import threading
from http import client
import random
from scipy.signal import convolve


# Parámetros para la simulación de sincronización
periodo_sinc = 100  # Define el período para la señal sinc (puedes ajustar este valor)
sincronizado = True  # Controla si la comunicación está sincronizada o desincronizada

# Datos del broker
broker = "test.mosquitto.org"
port = 1883
topico_suscribir = "topico/wpp2"

# Configuración de la ventana principal
ventana = tk.Tk()
ventana.title("Análisis de Datos")
ventana.geometry("1920x1080")
ventana.configure(bg='#1c1c1c')  # Fondo oscuro

# Colores personalizados
color_fondo = '#1c1c1c'
color_texto = '#e0e0e0'
color_titulo = '#ff79c6'
color_label_bg = '#282a36'
color_grafico_bg = '#282a36'
color_grafico_linea = '#50fa7b'
color_scroll_texto_bg = '#282a36'
color_scroll_texto_fg = '#f8f8f2'

# Función para convertir un mensaje en bytes a binario
def bytes_a_binario(byte_data):
    return ''.join(format(byte, '08b') for byte in byte_data)

# Función para convertir un mensaje de texto a binario
def texto_a_binario(texto):
    return ''.join(format(ord(char), '08b') for char in texto)

# Función para convertir binario a ASCII
def binario_a_ascii(binario):
    return ''.join(chr(int(binario[i:i+8], 2)) for i in range(0, len(binario), 8))


def binario_a_hexadecimal(binario):
    """Convierte una cadena binaria en formato hexadecimal"""
    hex_value = hex(int(binario, 2))[2:]  # Convierte binario a hexadecimal
    return hex_value.upper().zfill(len(binario) // 4)  # Completa con ceros a la izquierda si es necesario

def binario_a_ascii(binario):
    """Convierte una cadena binaria en formato ASCII"""
    ascii_text = ''.join(chr(int(binario[i:i+8], 2)) for i in range(0, len(binario), 8))
    return ascii_text



def generar_diagrama_ojo(señal, M, T, d, L):
    """Genera el diagrama de ojo para una señal dada."""
    tiempo = np.arange(0, len(señal)) * T / M
    graficos["Diagrama de Ojo"].cla()  # Limpiar gráfico anterior

    # Parámetros de ajuste
    num_segmentos = 150  # Número máximo de segmentos a mostrar
    paso_segmento = max(1, len(señal) // (num_segmentos * M))
    
    for i in range(L, len(señal) - L, paso_segmento):
        inicio = (i - L) * M
        fin = (i + L + 1) * M
        if fin > len(señal):
            break
        segmento = señal[inicio:fin]
        tiempo_segmento = np.arange(-L * T, (L + 1) * T, T / M)
        
        # Asegurarse de que las dimensiones coincidan
        if len(tiempo_segmento) != len(segmento):
            continue
        
        graficos["Diagrama de Ojo"].plot(tiempo_segmento, segmento, color=color_grafico_linea, alpha=0.5)
    
    graficos["Diagrama de Ojo"].set_xlim([-5, 5])
    graficos["Diagrama de Ojo"].set_ylim([min(señal), max(señal)])
    graficos["Diagrama de Ojo"].set_xlabel("Tiempo", color=color_texto)
    graficos["Diagrama de Ojo"].set_ylabel("Amplitud", color=color_texto)
    graficos["Diagrama de Ojo"].spines['bottom'].set_color(color_texto)
    graficos["Diagrama de Ojo"].spines['left'].set_color(color_texto)
    graficos["Diagrama de Ojo"].tick_params(axis='x', colors=color_texto)
    graficos["Diagrama de Ojo"].tick_params(axis='y', colors=color_texto)
    canvas_list["Diagrama de Ojo"].draw()

# Funciones para crear los gráficos en la interfaz
def crear_grafico(frame):
    figura = plt.Figure(figsize=(5, 3), dpi=100)
    ax = figura.add_subplot(111)
    ax.set_facecolor(color_grafico_bg)
    figura.patch.set_facecolor(color_grafico_bg)
    
    # Configuración de colores para los ejes
    ax.spines['bottom'].set_color(color_texto)  # Ejes en blanco
    ax.spines['left'].set_color(color_texto)
    ax.tick_params(axis='x', colors=color_texto)
    ax.tick_params(axis='y', colors=color_texto)
    
    # Configuración para las líneas de los gráficos
    ax.plot([], color=color_grafico_linea)  # Línea verde
    
    canvas = FigureCanvasTkAgg(figura, master=frame)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    return ax, canvas

# Creación de los frames donde se ubicarán los gráficos
# Creación de los frames donde se ubicarán los gráficos
frames = {}
graficos = {}
canvas_list = {}

titulos = [
    "Mensaje filtrado", "Mensaje TCP", "Mensaje PAM4", 
    "Mensaje STOMP", "Mensaje Ethernet", "Mensaje en Binario", 
    "Diagrama de Ojo", "Mensaje IP"
]

# Añadimos la posición para cada título, dejando la posición (3, 1) libre para el ScrolledText
posiciones = [(0, 0), (0, 1), (1, 0), (1, 1), (2, 0), (2, 1), (0, 2, 3), (3, 0)]

for i, titulo in enumerate(titulos):
    row, col = posiciones[i][:2]
    rowspan = posiciones[i][2] if len(posiciones[i]) > 2 else 1
    frame = tk.Frame(ventana, bg=color_fondo)
    frame.grid(row=row, column=col, rowspan=rowspan, padx=10, pady=10, sticky="nsew")
    tk.Label(frame, text=titulo, font=("Helvetica", 12), fg=color_titulo, bg=color_label_bg).pack(fill=tk.X, padx=5, pady=5)
    ax, canvas = crear_grafico(frame)
    graficos[titulo] = ax
    canvas_list[titulo] = canvas

    # Ya no creamos el ScrolledText aquí para "Mensaje en Binario"
    frames[titulo] = (frame, None)

# Ahora, creamos el ScrolledText en la posición (3, 1)
frame_binario = tk.Frame(ventana, bg=color_fondo)
frame_binario.grid(row=3, column=1, padx=10, pady=10, sticky="nsew")
tk.Label(frame_binario, text="Mensaje en Binario", font=("Helvetica", 12), fg=color_titulo, bg=color_label_bg).pack(fill=tk.X, padx=5, pady=5)

# Crear un ScrolledText para mostrar los mensajes en ASCII en la nueva posición
texto_area = scrolledtext.ScrolledText(frame_binario, wrap=tk.WORD, font=("Helvetica", 12), fg=color_scroll_texto_fg, bg=color_scroll_texto_bg, padx=10, pady=10, height=10, width=40)
texto_area.pack(pady=5)
frames["Mensaje en Binario"] = (frame_binario, texto_area)

# Configuraciones para que las filas y columnas puedan expandirse
ventana.grid_rowconfigure(0, weight=1)
ventana.grid_rowconfigure(1, weight=1)
ventana.grid_rowconfigure(2, weight=1)
ventana.grid_rowconfigure(3, weight=1)  # La fila 3 tiene el gráfico "Mensaje IP" y el ScrolledText
ventana.grid_columnconfigure(0, weight=1)
ventana.grid_columnconfigure(1, weight=1)
ventana.grid_columnconfigure(2, weight=2)


def binario_a_bytes(binario):
    binario_filtrado = ''.join(c for c in binario if c in '01')
    byte_array = bytearray()
    for i in range(0, len(binario_filtrado), 8):
        byte_chunk = binario_filtrado[i:i + 8].ljust(8, '0')
        byte = int(byte_chunk, 2)
        byte_array.append(byte)
    return bytes(byte_array)

def sinc_filter(length, alpha):
    t = np.arange(-length // 2, length // 2 + 1)
    return np.sinc(t / alpha)

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


def alternar_sincronizacion():
    global sincronizado
    sincronizado = not sincronizado
    estado = "sincronizado" if sincronizado else "desincronizado"


def aplicar_desincronizacion(signal, periodo):
    desincronizado_signal = np.roll(signal, shift=periodo)
    return desincronizado_signal

def on_message(client, userdata, msg):
    # Recibir el mensaje como una lista de bits o flotantes
    mensaje_bits = msg.payload.decode()

    frames["Mensaje en Binario"][1].config(state=tk.NORMAL)
    frames["Mensaje en Binario"][1].delete('1.0', tk.END)

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
        frames["Mensaje en Binario"][1].insert(tk.END, "Mensaje Ethernet:\n" + str(ethernet_encabezado) + "\n\n")
        frames["Mensaje en Binario"][1].insert(tk.END, "Mensaje Ethernet Bin:\n" + str(ethernet_message_bin) + "\n\n")
        ip_message_bin = ethernet_encabezado['payload']
        print(f"Mensaje IP binario: {ip_message_bin}")
    except ValueError as e:
        print(f"Error desencapsulando Ethernet: {e}")
        return

    # Decodificar IP
    try:
        ip_encabezado = decodificar_encabezado_ip(ip_message_bin)
        print(f"Encabezado IP: {ip_encabezado}")
        frames["Mensaje en Binario"][1].insert(tk.END, "Mensaje IP:\n" + str(ip_encabezado) + "\n\n")
        frames["Mensaje en Binario"][1].insert(tk.END, "Mensaje IP bin:\n" + str(ip_message_bin) + "\n\n")
        tcp_message_bin = ip_encabezado['payload']
        print(f"Mensaje TCP binario: {tcp_message_bin}")
    except ValueError as e:
        print(f"Error desencapsulando IP: {e}")
        return


    # Decodificar TCP
    try:
        tcp_encabezado = decodificar_encabezado_tcp(tcp_message_bin)
        print(f"Encabezado TCP: {tcp_encabezado}")
        frames["Mensaje en Binario"][1].insert(tk.END, "Mensaje TCP:\n" + str(tcp_encabezado) + "\n\n")
        frames["Mensaje en Binario"][1].insert(tk.END, "Mensaje TCP bin:\n" + str(tcp_message_bin) + "\n\n")
        stomp_message_bin = tcp_encabezado['payload']
        print(f"Mensaje STOMP binario: {stomp_message_bin}")
    except ValueError as e:
        print(f"Error desencapsulando TCP: {e}")
        return

    # Decodificar STOMP
    try:
        stomp_mensaje = decodificar_stomp(stomp_message_bin)
        print(f"Mensaje STOMP: {stomp_mensaje}")
        frames["Mensaje en Binario"][1].insert(tk.END, "Mensaje STOMP:\n" + str(stomp_mensaje) + "\n\n")
        frames["Mensaje en Binario"][1].insert(tk.END, "Mensaje STOMP bin:\n" + str(stomp_message_bin) + "\n\n")
        id_remitente , mensaje_recibido = stomp_mensaje.split('SEND\ndestination:/queue/test:\n\n-STOMP' , 1)
        print(f"ID de remitente: {id_remitente}")
        print(f"Mensaje recibido: {mensaje_recibido}")
    except ValueError as e:
        print(f"Error desencapsulando STOMP: {e}")
        return

    mensaje_recibido_bin = texto_a_binario(mensaje_recibido)
    stomp_message_bin = texto_a_binario(stomp_mensaje)
    stomp_message_binario_lista = [int(bit) for bit in stomp_message_bin]

    # Actualizar gráfico "Mensaje en Binario"
    mensaje_binario_lista_original = [int(bit) for bit in mensaje_recibido_bin]  # Usar el binario directamente

    graficos["Mensaje en Binario"].cla()
    graficos["Mensaje en Binario"].plot(mensaje_binario_lista_original, color=color_grafico_linea)
    canvas_list["Mensaje en Binario"].draw()


    
    # Graficar mensajes y señales
    graficos["Mensaje filtrado"].cla()
    graficos["Mensaje filtrado"].plot(convolucionada[:100], color=color_grafico_linea)
    canvas_list["Mensaje filtrado"].draw()

    graficos["Mensaje TCP"].cla()
    graficos["Mensaje TCP"].plot([int(bit) for bit in tcp_message_bin], color=color_grafico_linea)
    canvas_list["Mensaje TCP"].draw()
    
    graficos["Mensaje PAM4"].cla()
    graficos["Mensaje PAM4"].plot(pam4_signal[:100], color=color_grafico_linea)
    canvas_list["Mensaje PAM4"].draw()
    
    graficos["Mensaje STOMP"].cla()
    graficos["Mensaje STOMP"].plot(stomp_message_binario_lista, color=color_grafico_linea)
    canvas_list["Mensaje STOMP"].draw()
    
    graficos["Mensaje Ethernet"].cla()
    graficos["Mensaje Ethernet"].plot([int(bit) for bit in ethernet_message_bin], color=color_grafico_linea)
    canvas_list["Mensaje Ethernet"].draw()
    
    graficos["Mensaje IP"].cla()  # Limpiar el gráfico existente
    graficos["Mensaje IP"].plot([int(bit) for bit in ip_message_bin], color=color_grafico_linea)
    canvas_list["Mensaje IP"].draw()
    

    frames["Mensaje en Binario"][1].insert(tk.END, "Mensaje recibido:\n" + mensaje_recibido + "\n\n")
    frames["Mensaje en Binario"][1].insert(tk.END, "\n Mensaje recibido en binario:\n" + str(mensaje_recibido_bin) + "\n\n")

    frames["Mensaje en Binario"][1].config(state=tk.DISABLED)

    generar_diagrama_ojo(convolucionada, 1, 1, 10, 10)

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


client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

# Conectar al broker en un hilo separado
def conectar_mqtt():
    client.connect(broker, port)
    client.loop_forever()

mqtt_thread = threading.Thread(target=conectar_mqtt)
mqtt_thread.start() 

ventana.mainloop()
