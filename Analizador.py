import pyshark
from collections import defaultdict
from datetime import datetime
import joblib
import numpy as np
import os

def construir_vector_paquete(pkt):
    def extraer_campo(layer, campo, default=0):
        try:
            return int(getattr(getattr(pkt, layer), campo))
        except:
            return default

    dst_port = extraer_campo('tcp', 'dstport') if 'TCP' in pkt else extraer_campo('udp', 'dstport')
    flow_duration = 0
    total_fwd = 1
    total_bwd = 1
    pkt_len = int(pkt.length) if hasattr(pkt, 'length') else 0
    fwd_len_max = fwd_len_min = fwd_len_mean = pkt_len
    bwd_len_max = bwd_len_min = bwd_len_mean = pkt_len
    bytes_per_sec = pkt_len
    pkts_per_sec = 1
    fwd_header = extraer_campo('tcp', 'hdr_len') if 'TCP' in pkt else 0
    bwd_header = 0
    pkt_len_mean = pkt_len
    pkt_len_std = 0

    syn_flag = fin_flag = ack_flag = urg_flag = 0
    if 'TCP' in pkt:
        try:
            flags = int(pkt.tcp.flags, 16)
            syn_flag = 1 if flags & 0x02 else 0
            fin_flag = 1 if flags & 0x01 else 0
            ack_flag = 1 if flags & 0x10 else 0
            urg_flag = 1 if flags & 0x20 else 0
        except:
            pass

    vector = [
        dst_port, flow_duration, total_fwd, total_bwd,
        fwd_len_max, fwd_len_min, fwd_len_mean,
        bwd_len_max, bwd_len_min, bwd_len_mean,
        bytes_per_sec, pkts_per_sec,
        fwd_header, bwd_header, pkt_len_mean,
        pkt_len_std, syn_flag, fin_flag, ack_flag, urg_flag
    ]
    return np.array(vector).reshape(1, -1)

class AnalizadorVulnerabilidades:
    def __init__(self, modelo_path='modelo_randomforest.pkl'):
        self.alertas = []
        self.modelo = None
        self.conteo_ips = defaultdict(int)
        self.timestamps_por_ip = defaultdict(list)

        try:
            ruta_modelo = os.path.join(os.path.dirname(__file__), modelo_path)
            self.modelo = joblib.load(ruta_modelo)
        except Exception as e:
            self.alertas.append(f"[ERROR] No se pudo cargar el modelo: {e}")

    def evaluar_paquete(self, pkt):
        if 'IP' not in pkt or not self.modelo:
            return False
        try:
            features = construir_vector_paquete(pkt)
            pred = self.modelo.predict(features)
            return pred[0] == 0  # 0 = amenaza, 1 = benigno
        except Exception as e:
            self.alertas.append(f"[ERROR ML] {e}")
            return False

    def analizar_archivo(self, archivo_pcap):
        try:
            cap = pyshark.FileCapture(archivo_pcap)
        except Exception as e:
            self.alertas.append(f"[ERROR] No se pudo abrir el archivo: {e}")
            return

        for pkt in cap:
            try:
                self._analizar_paquete(pkt)
            except:
                continue

        cap.close()
        self.detectar_dos_simples()
        self.mostrar_ips_activas()

    def _analizar_paquete(self, pkt):
        if 'IP' in pkt:
            src = pkt.ip.src
            self.conteo_ips[src] += 1
            if hasattr(pkt, 'sniff_time'):
                self.timestamps_por_ip[src].append(pkt.sniff_time)

            if self.evaluar_paquete(pkt):
                self.alertas.append(f"🚨 AMENAZA detectada por modelo ML desde {src}")

    def detectar_dos_simples(self):
        for ip, tiempos in self.timestamps_por_ip.items():
            if len(tiempos) >= 10:
                tiempos.sort()
                intervalo = (tiempos[-1] - tiempos[0]).total_seconds()
                if intervalo < 5:
                    self.alertas.append(f"⚠️ Posible ataque DoS desde {ip}: {len(tiempos)} paquetes en {intervalo:.2f}s")

    def mostrar_ips_activas(self):
        ip_ordenadas = sorted(self.conteo_ips.items(), key=lambda x: x[1], reverse=True)
        self.alertas.append("\n📊 IPs más activas:")
        if not ip_ordenadas:
            self.alertas.append("No se detectaron IPs activas.")
            return
        for ip, count in ip_ordenadas[:5]:
            self.alertas.append(f"{ip} → {count} paquetes")


