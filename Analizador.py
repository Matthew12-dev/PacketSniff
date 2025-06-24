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

def detectar_por_heuristica(pkt):
    try:
        if 'IP' not in pkt:
            return False, ""

        ip = pkt.ip
        proto = pkt.transport_layer if hasattr(pkt, 'transport_layer') else None
        dst_port = int(pkt[pkt.transport_layer].dstport) if proto in ['TCP', 'UDP'] else None

        puertos_riesgo = [23, 2323, 31337, 4444, 5555, 6667, 1337]
        if dst_port in puertos_riesgo:
            return True, f"Puerto destino sospechoso: {dst_port}"

        if hasattr(ip, 'ttl') and int(ip.ttl) <= 1:
            return True, f"TTL muy bajo: {ip.ttl}"

        if hasattr(pkt, 'length'):
            length = int(pkt.length)
            if length > 1500:
                return True, f"Paquete demasiado grande: {length} bytes"
            if length < 40:
                return True, f"Paquete demasiado pequeño: {length} bytes"

        if proto not in ['TCP', 'UDP', 'ICMP']:
            return True, f"Protocolo inusual: {proto}"

        return False, ""

    except Exception as e:
        return False, f"[ERROR heurística] {e}"
    
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
       if 'IP' not in pkt:
        return False

       try:
         heuristica, _ = detectar_por_heuristica(pkt)
         if heuristica:
            return True
         # Si no fue detectado por heurísticas, usar modelo ML
         if self.modelo:
            features = construir_vector_paquete(pkt)
            pred = self.modelo.predict(features)
            return pred[0] == 0  # 0 = amenaza

       except:
          return False

       return False  # Si no hay alerta

    def analizar_archivo(self, archivo_pcap):
        try:
            cap = pyshark.FileCapture(archivo_pcap)
        except Exception as e:
            self.alertas.append(f"[ERROR] No se pudo abrir el archivo: {e}")
            return

        for pkt in cap:
           try:
              if 'IP' not in pkt:
                continue

              heur, razon = detectar_por_heuristica(pkt)
              if heur:
                self.alertas.append(f"[HEURÍSTICA] {razon}")
                continue  # Ya se detectó por heurística

            # Si no heurística, usar ML si está disponible
              if self.modelo:
                 features = construir_vector_paquete(pkt)
                 pred = self.modelo.predict(features)
                 if pred[0] == 0:
                     self.alertas.append(f"[ML] Amenaza detectada por modelo en paquete IP {pkt.ip.src} -> {pkt.ip.dst}")

           except Exception as e:
               self.alertas.append(f"[ERROR en paquete] {e}")
               continue

        cap.close()
        self.mostrar_ips_activas()

        print("\n📌 RESUMEN DE ALERTAS:")
        for alerta in self.alertas:
            print(alerta)
            
    def _analizar_paquete(self, pkt):
        if 'IP' in pkt:
            src = pkt.ip.src
            self.conteo_ips[src] += 1
            if hasattr(pkt, 'sniff_time'):
                self.timestamps_por_ip[src].append(pkt.sniff_time)

            if self.evaluar_paquete(pkt):
                self.alertas.append(f"🚨 AMENAZA detectada por modelo ML desde {src}")

    def mostrar_ips_activas(self):
        ip_ordenadas = sorted(self.conteo_ips.items(), key=lambda x: x[1], reverse=True)
        self.alertas.append("\n📊 IPs más activas:")
        if not ip_ordenadas:
            self.alertas.append("No se detectaron IPs activas.")
            return
        for ip, count in ip_ordenadas[:5]:
            self.alertas.append(f"{ip} → {count} paquetes")



