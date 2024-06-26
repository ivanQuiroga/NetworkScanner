import os
import subprocess
import time
import logging
import socket
import signal
import threading
import argparse
from scapy.all import *
import requests
import whois

# Configuración de bitácora y consola
LOG_FILE = "..\\network_activity.log"
EXCLUDE_FILE=".\\exclude.txt"

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', handlers=[
    logging.FileHandler(LOG_FILE),
    logging.StreamHandler()
])

# Directorio de captura
CAPTURE_DIR = "..\\network_captures"
if not os.path.exists(CAPTURE_DIR):
    os.makedirs(CAPTURE_DIR)

# Evento de threading para detener los hilos
stop_event = threading.Event()

# Exclusion de IP
def load_exclude_ips(file_path):
    if not os.path.exists(file_path):
        return set()
    with open(file_path, 'r') as file:
        return set(line.strip() for line in file if line.strip())
    
exclude_ips = load_exclude_ips(EXCLUDE_FILE)

# Función para enviar notificaciones usando PowerShell
def send_windows_notification(title, message):
    script_path = "send_notifications.ps1"
    subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path, "-title", title, "-message", message])

# Función para obtener el nombre del host de una IP
def get_host_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

# Función para obtener información adicional de una IP usando WHOIS y GeoIP
def get_ip_info(ip):
    try:
        whois_info = whois.whois(ip)
        whois_details = f"WHOIS info: {whois_info.org}, {whois_info.address}, {whois_info.country}"
    except Exception as e:
        whois_details = f"WHOIS info: {str(e)}"
    
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        geoip_info = response.json()
        geoip_details = f"GeoIP info: {geoip_info.get('city')}, {geoip_info.get('region')}, {geoip_info.get('country')}"
    except Exception as e:
        geoip_details = f"GeoIP info: {str(e)}"
    
    return whois_details, geoip_details

# Función para registrar eventos en la bitácora y en la consola
def log_event(event):
    logging.info(event)
    print(event)

# Función para analizar paquetes
def analyze_packet(packet):
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in exclude_ips or dst_ip in exclude_ips:
            return

        dst_port = packet[TCP].dport
        src_host = get_host_name(src_ip)
        dst_host = get_host_name(dst_ip)

        whois_details, geoip_details = get_ip_info(dst_ip)

        # Detectar escaneo de puertos (SYN scan)
        if flags == 'S':
            alert = f"Posible escaneo de puerto detectado desde {src_ip} ({src_host}) hacia {dst_ip}:{dst_port} ({dst_host})\n{whois_details}\n{geoip_details}"
            send_windows_notification("Alerta de Seguridad", alert)
            log_event(alert)

        # Detectar conexiones importantes (puertos específicos)
        if dst_port in [22, 80, 443, 3389]:  # Puertos SSH, HTTP, HTTPS, RDP
            alert = f"Conexión importante detectada desde {src_ip} ({src_host}) hacia {dst_ip}:{dst_port} ({dst_host})\n{whois_details}\n{geoip_details}"
            send_windows_notification("Alerta de Seguridad", alert)
            log_event(alert)

        # Detectar intentos de conexión a puertos sensibles
        if dst_port in range(0, 1024):  # Puertos reservados
            alert = f"Intento de conexión a puerto reservado {dst_ip}:{dst_port} ({dst_host}) desde {src_ip} ({src_host})\n{whois_details}\n{geoip_details}"
            send_windows_notification("Alerta de Seguridad", alert)
            log_event(alert)

# Función para analizar el archivo de captura
def analyze_capture_file(capture_file):
    print(f"Analizando el archivo de captura: {capture_file}")
    packets = rdpcap(capture_file)
    for packet in packets:
        analyze_packet(packet)

# Función para capturar tráfico de red
def capture_traffic(interface):
    while not stop_event.is_set():
        # Limpieza de archivos antiguos
        cleanup_old_files()
        # Obtener filtro de IPs locales
        ip_filter = generate_ip_filter()

        # Comando de tshark para capturar tráfico
        capture_file = os.path.join(CAPTURE_DIR, f"capture_{int(time.time())}.pcap")
        tshark_command = [
            "tshark", "-i", interface, "-f", ip_filter,
            "-w", capture_file,
            "-a", "duration:60"  # Captura de 1 minuto
        ]
        print(f"Ejecutando: {' '.join(tshark_command)}")
        subprocess.run(tshark_command)

        # Esperar 10 segundos antes de la próxima captura
        stop_event.wait(10)

# Función para analizar los archivos de captura
def analyze_files():
    while not stop_event.is_set():
        for root, dirs, files in os.walk(CAPTURE_DIR):
            for file in files:
                file_path = os.path.join(root, file)
                analyze_capture_file(file_path)
                # Eliminar archivo después de analizar
                os.remove(file_path)
        # Esperar 10 segundos antes de la próxima revisión
        stop_event.wait(10)

def cleanup_old_files():
    current_time = time.time()
    for root, dirs, files in os.walk(CAPTURE_DIR):
        for file in files:
            file_path = os.path.join(root, file)
            # Eliminar archivos que tengan más de una hora
            if os.path.getmtime(file_path) < current_time - 3600:
                os.remove(file_path)

def generate_ip_filter():
    ips = get_local_ips()
    filter = " or ".join(f"host {ip}" for ip in ips)
    return filter

def get_local_ips():
    hostname = socket.gethostname()
    ips = socket.gethostbyname_ex(hostname)[2]
    return ips

def signal_handler(sig, frame):
    print('Interrumpido! Cerrando hilos...')
    stop_event.set()

if __name__ == "__main__":
    # Configurar el manejador de señales
    signal.signal(signal.SIGINT, signal_handler)

    # Argument parser
    parser = argparse.ArgumentParser(description='Monitor de tráfico de red')
    parser.add_argument('-i', '--interface', type=str, required=True, help='Interfaz de red para capturar tráfico')
    args = parser.parse_args()

    # Crear hilos para captura y análisis
    capture_thread = threading.Thread(target=capture_traffic, args=(args.interface,))
    analyze_thread = threading.Thread(target=analyze_files)

    # Iniciar hilos
    capture_thread.start()
    analyze_thread.start()

    # Esperar a que los hilos terminen (nunca terminan en este caso)
    capture_thread.join()
    analyze_thread.join()
