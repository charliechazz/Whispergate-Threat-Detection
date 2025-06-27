import sys
import os
import pickle
import pandas as pd
import numpy as np
from scapy.all import sniff
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
import warnings
import time
from threading import Thread

warnings.simplefilter(action='ignore', category=FutureWarning)

LOG_FILE = "shared_event_log.txt"

def log_event(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] IDS: {message}\n")

def monitor_log():
    """Monitorea eventos escritos por el IPS"""
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                if "IPS:" in line:
                    print(f"[IDS] IPS escribió: {line.strip()}")
            else:
                time.sleep(0.5)

# Inicia monitoreo del log en segundo plano
Thread(target=monitor_log, daemon=True).start()

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class AnomalIA_IDS:
    def __init__(self, model_path, scaler_path, pca_path):
        self.model = self.load_pickle(resource_path(model_path))
        self.scaler = self.load_pickle(resource_path(scaler_path))
        self.pca = self.load_pickle(resource_path(pca_path))

        if not hasattr(self.pca, "n_components_"):
            raise ValueError("El PCA cargado no tiene el atributo 'n_components_'.")

        self.n_components = self.pca.n_components_
        print(f"✅ PCA detectado con {self.n_components} componentes.")

        self.original_features = getattr(self.scaler, "feature_names_in_", None)
        if self.original_features is None:
            raise ValueError("❌ No se pudieron obtener las características originales del scaler.")

        print(f"✅ Se encontraron {len(self.original_features)} características usadas en el entrenamiento.")

        if self.n_components > 10:
            print(f"⚠️ El PCA tiene {self.n_components} componentes, se usarán solo 10.")
            self.n_components = 10

    def load_pickle(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            raise RuntimeError(f"Error al cargar '{file_path}': {e}")

    def predict_intrusion(self, data_dict):
        try:
            data_df = pd.DataFrame([data_dict])
            for col in self.original_features:
                if col not in data_df:
                    data_df[col] = 0
            data_df = data_df[self.original_features]

            data_scaled = self.scaler.transform(data_df)
            data_pca = self.pca.transform(data_scaled)[:, :self.n_components]
            df_pca = pd.DataFrame(data_pca, columns=[f'pc{i+1}' for i in range(self.n_components)])

            predicted_bin = self.model["stacking_bin"].predict(df_pca)[0]
            predicted_multi = self.model["stacking_multi"].predict(df_pca)[0] if predicted_bin == 1 else "BENIGN"

            return predicted_bin, predicted_multi

        except Exception as e:
            print(f"❌ Error en la predicción: {e}")
            return None, None

def extract_features(packet):
    try:
        features = {
            "timestamp": packet.time,
            "proto": packet.proto if isinstance(packet.proto, int) else 0,
            "sport": packet.sport if isinstance(packet.sport, int) else 0,
            "dport": packet.dport if isinstance(packet.dport, int) else 0,
            "length": len(packet),
            "flags": packet.flags.value if hasattr(packet.flags, 'value') else 0,
            "ttl": packet.ttl if isinstance(packet.ttl, int) else 0,
        }
        return features
    except Exception as e:
        print(f"Error al extraer características: {e}")
        return {}

def packet_callback(packet):
    try:
        features = extract_features(packet)
        prediction = anomaly_detector.predict_intrusion(features)
        if prediction[0] == 0:
            print(f"Paquete Benigno: {packet.summary()}")
        else:
            print(f"🚨 Posible Ataque Detectado: {packet.summary()}")
            log_event(f"Ataque detectado por IDS - Tipo: {prediction[1]} - {packet.summary()}")
    except Exception as e:
        print(f"Error al procesar el paquete: {e}")

model_path = "hybrid_lightgbm_lr_model.pkl"
scaler_path = "scaler.pkl"
pca_path = "pca.pkl"

anomaly_detector = AnomalIA_IDS(model_path, scaler_path, pca_path)

print("Comenzando la captura de paquetes...")
sniff(prn=packet_callback, store=0)
