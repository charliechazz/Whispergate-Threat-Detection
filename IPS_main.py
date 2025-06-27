import sys
import os
from scapy.all import *
import time
import joblib
import warnings
from threading import Thread

warnings.filterwarnings("ignore")

LOG_FILE = "shared_event_log.txt"

def log_event(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] IPS: {message}\n")

def monitor_log():
    """Monitorea eventos escritos por el IDS"""
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                if "IDS:" in line:
                    print(f"[IPS] IDS escribió: {line.strip()}")
            else:
                time.sleep(0.5)

# Inicia monitoreo del log en segundo plano
Thread(target=monitor_log, daemon=True).start()

# Función para obtener ruta en PyInstaller
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class AnomalIA_IPS:
    def __init__(self, binary_model, multi_model):
        self.binary_model = joblib.load(resource_path(binary_model))
        self.multi_model = joblib.load(resource_path(multi_model))

    def predict_anomaly(self, data_dict):
        try:
            data_array = [[data_dict[key] for key in sorted(data_dict.keys())]]
            return self.binary_model.predict(data_array)[0]
        except:
            return None

    def predict_attack(self, data_dict):
        try:
            data_array = [[data_dict[key] for key in sorted(data_dict.keys())]]
            return self.multi_model.predict(data_array)[0]
        except:
            return None

ia = AnomalIA_IPS("binary_ensemble_model.pkl", "boosting_ensemble_multimodel.pkl")
last_time = None
last_size = None

def calculate_dload(packet):
    global last_time, last_size
    current_time = time.time()
    size = len(packet)
    if last_time is None:
        last_time = current_time
        last_size = size
        return 0.0
    else:
        dload = abs((size - last_size) / (current_time - last_time))
        last_time = current_time
        last_size = size
        return dload

def process_packet(packet):
    global last_time, last_size

    if IP in packet:
        proto = packet[IP].proto
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sttl = packet[IP].ttl if IP in packet else 0
        dload = calculate_dload(packet)

        if proto == 6:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            state = packet[TCP].sprintf('%TCP.flags%')
        elif proto == 17:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            state = None
        else:
            src_port = dst_port = 0
            state = None

        data = {
            "sttl": sttl,
            "proto_tcp": 1 if proto == 6 else 0,
            "dload": dload,
        }

        if ia.predict_anomaly(data) == 1:
            tipo = ia.predict_attack(data)
            print("🚨 ATAQUE DETECTADO!")
            print("Tipo de anomalía:", tipo)
            log_event(f"Ataque detectado por IPS - Tipo: {tipo} de {src_ip} a {dst_ip}")

        print(f"PROTO: {proto}, SRC: {src_ip}:{src_port}, DST: {dst_ip}:{dst_port}, STTL: {sttl}, DLOAD: {dload}, STATE: {state}")

print("Capturando paquetes en tiempo real...")
sniff(prn=process_packet, store=0)
