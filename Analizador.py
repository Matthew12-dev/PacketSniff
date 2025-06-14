import pyshark
from collections import defaultdict
from datetime import datetime
import joblib
import numpy as np

class AnalizadorVulnerabilidades:
    def __init__(self, archivo_pcap, modelo_path='modelo_entrenado.pkl'):
        self.archivo_pcap = archivo_pcap
        self.alertas = []
        self.cap = None
        self.conteo_ips = defaultdict(int)
        self.mac_por_ip = defaultdict(set)
        self.dominios_dns = defaultdict(set)
        self.timestamps_por_ip = defaultdict(list)

        try:
            self.cap = pyshark.FileCapture(self.archivo_pcap)
            self.modelo = joblib.load(modelo_path)
        except Exception as e:
            self.alertas.append(f"[ERROR] No se pudo abrir el archivo o cargar el modelo: {e}")

    def analizar_paquetes(self):
        if not self.cap:
            return

        for pkt in self.cap:
            try:
                if 'IP' in pkt:
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                    self.conteo_ips[src] += 1
                    if hasattr(pkt, 'sniff_time'):
                        self.timestamps_por_ip[src].append(pkt.sniff_time)

                if 'HTTP' in pkt:
                    msg = f"ALERTA: HTTP sin cifrado: {pkt.ip.src} → {pkt.ip.dst}"
                    self.alertas.append(msg)
                    if hasattr(pkt.http, 'authorization'):
                        self.alertas.append(f"ALERTA: Credenciales HTTP detectadas: {pkt.http.authorization}")

                if 'TCP' in pkt:
                    flags = getattr(pkt.tcp, 'flags', None)
                    if flags:
                        flags = int(flags, 16)
                        if flags == 0:
                            self.alertas.append(f"ALERTA: TCP NULL scan: {pkt.ip.src} → {pkt.ip.dst}")
                        elif flags == 1:
                            self.alertas.append(f"ALERTA: TCP FIN scan: {pkt.ip.src} → {pkt.ip.dst}")
                        elif flags == 41:
                            self.alertas.append(f"ALERTA: TCP XMAS scan: {pkt.ip.src} → {pkt.ip.dst}")

                if 'FTP' in pkt:
                    self.alertas.append(f"ALERTA: Tráfico FTP detectado: {pkt.ip.src} → {pkt.ip.dst}")

                if 'TELNET' in pkt:
                    self.alertas.append(f"ALERTA: Tráfico TELNET inseguro: {pkt.ip.src} → {pkt.ip.dst}")

                if 'ARP' in pkt:
                    ip = pkt.arp.psrc
                    mac = pkt.arp.hwsrc
                    self.mac_por_ip[ip].add(mac)
                    if len(self.mac_por_ip[ip]) > 1:
                        self.alertas.append(f"ALERTA: ARP Spoofing: {ip} tiene múltiples MACs: {self.mac_por_ip[ip]}")

                if 'HTTP' in pkt and hasattr(pkt.http, 'request_uri'):
                    uri = pkt.http.request_uri.lower()
                    patrones_inyeccion = ["'", "--", "<script>", "or 1=1", "drop table"]
                    if any(p in uri for p in patrones_inyeccion):
                        self.alertas.append(f"ALERTA: Posible inyección desde {pkt.ip.src} → URI: {uri}")

                # Características para el modelo ML:
                if 'IP' in pkt:
                    ttl = int(pkt.ip.ttl) if hasattr(pkt.ip, 'ttl') else 64
                    length = int(getattr(pkt, 'length', 0))
                    num_dns = len(self.dominios_dns[pkt.ip.src])
                    dns_request = 1 if 'DNS' in pkt else 0
                    features = np.array([[ttl, length, num_dns, dns_request]])

                    try:
                        pred = self.modelo.predict(features)
                        if pred[0] == 1:
                            self.alertas.append(f"⚠️ ML: Tráfico sospechoso detectado desde {pkt.ip.src}")
                    except Exception as e:
                        self.alertas.append(f"[ERROR ML] {e}")

            except Exception as e:
                continue

        self.detectar_dos_simples()

    def detectar_dos_simples(self):
        for ip, tiempos in self.timestamps_por_ip.items():
            if len(tiempos) >= 10:
                tiempos.sort()
                intervalo = (tiempos[-1] - tiempos[0]).total_seconds()
                if intervalo < 5:
                    self.alertas.append(f"ALERTA: Posible ataque DoS desde {ip} con {len(tiempos)} paquetes en {intervalo:.2f}s")

    def mostrar_ips_activas(self):
        ip_ordenadas = sorted(self.conteo_ips.items(), key=lambda x: x[1], reverse=True)
        self.alertas.append("\n🔝 IPs más activas:")
        for ip, count in ip_ordenadas[:5]:
            self.alertas.append(f"{ip} → {count} paquetes")

