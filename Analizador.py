import pyshark
from collections import defaultdict,deque
from datetime import datetime,timedelta
import joblib
import numpy as np
import os

class Flujo:
    def __init__(self, clave):
        self.clave = clave
        self.paquetes = []
        self.tiempos = []

    def agregar(self, pkt):
        self.paquetes.append(pkt)
        if hasattr(pkt, 'sniff_time'):
            self.tiempos.append(pkt.sniff_time)

    def calcular_vector(self):
        if not self.paquetes:
            return None

        fwd_lens = []
        bwd_lens = []
        total_bytes = 0
        total_pkts = len(self.paquetes)
        syn = fin = ack = urg = 0

        ip_src, ip_dst, src_port, dst_port, proto = self.clave
        for pkt in self.paquetes:
            try:
                pkt_len = len(pkt.get_raw_packet())
                total_bytes += pkt_len

                direccion = (pkt.ip.src == ip_src)
                if direccion:
                    fwd_lens.append(pkt_len)
                else:
                    bwd_lens.append(pkt_len)

                if 'TCP' in pkt:
                    flags = int(pkt.tcp.flags, 16)
                    syn += 1 if flags & 0x02 else 0
                    fin += 1 if flags & 0x01 else 0
                    ack += 1 if flags & 0x10 else 0
                    urg += 1 if flags & 0x20 else 0
            except:
                continue

        fwd_stats = np.array(fwd_lens) if fwd_lens else np.zeros(1)
        bwd_stats = np.array(bwd_lens) if bwd_lens else np.zeros(1)
        dur = (max(self.tiempos) - min(self.tiempos)).total_seconds() if self.tiempos else 0.0001

        vector = [
            int(dst_port),
            dur,
            len(fwd_lens),
            len(bwd_lens),
            fwd_stats.max(),
            fwd_stats.min(),
            fwd_stats.mean(),
            bwd_stats.max(),
            bwd_stats.min(),
            bwd_stats.mean(),
            total_bytes / dur,
            total_pkts / dur,
            0, 0,
            total_bytes / total_pkts if total_pkts > 0 else 0,
            np.std(np.array([len(pkt.get_raw_packet()) for pkt in self.paquetes])),
            syn, fin, ack, urg
        ]
        return np.array(vector).reshape(1, -1)


class AnalizadorVulnerabilidades:
    def __init__(self, modelo_path='modelo_randomforest.pkl'):
        self.alertas = []
        self.mensajes_mostrados=set()
        self.mensajes_recientes = []
        self.modelo = None
        self.flujos = defaultdict(lambda: None)
        self.conteo_ips = defaultdict(int) 
        self.syn_por_ip = defaultdict(deque)
        self.limite_syn = 10  # puedes ajustar este umbral
        self.ventana_tiempo = timedelta(seconds=5)

        try:
            ruta_modelo = os.path.join(os.path.dirname(__file__), modelo_path)
            self.modelo, self.feature_names = joblib.load(ruta_modelo)
        except Exception as e:
            self.alertas.append(f"[ERROR] No se pudo cargar el modelo: {e}")

    def analizar_paquete_en_vivo(self, pkt):
        if 'IP' not in pkt:
            return
        try:
            self.mensajes_recientes.clear()  # ← limpiar mensajes previos en cada análisis

            proto = pkt.transport_layer if hasattr(pkt, 'transport_layer') else 'OTHR'

            if 'HTTP' in pkt:
                msg = "[HEURÍSTICA] Tráfico HTTP detectado"
                self.mensajes_recientes.append(msg)

            if hasattr(pkt, 'transport_layer'):
                proto = pkt.transport_layer
                if proto not in ['TCP', 'UDP', 'ICMP']:
                    msg = f"[HEURÍSTICA] Protocolo inusual: {proto}"
                    self.mensajes_recientes.append(msg)
            else:
                proto = None

            if hasattr(pkt.ip, 'ttl') and int(pkt.ip.ttl) <= 1:
                msg = f"[HEURÍSTICA] TTL muy bajo: {pkt.ip.ttl}"
                self.mensajes_recientes.append(msg)

            try:
                es_telnet = (
                    proto == "TCP" and (
                        pkt[proto].dstport == "23" or
                        (hasattr(pkt, 'layers') and 'TELNET' in pkt.layers)
                    )
                )
                if es_telnet:
                    msg = "[HEURÍSTICA] Tráfico TELNET detectado"
                    self.mensajes_recientes.append(msg)
            except:
                pass

            if 'DNS' in pkt:
                try:
                    nombre = pkt.dns.qry_name
                    if len(nombre) > 100:
                        msg = f"[HEURÍSTICA] Consulta DNS sospechosa/larga: {nombre[:60]}..."
                        self.mensajes_recientes.append(msg)
                except:
                    pass

            if pkt.highest_layer == "MDNS":
                msg = f"[HEURÍSTICA] Tráfico MDNS detectado desde {pkt.ip.src}"
                self.mensajes_recientes.append(msg)

            if 'TCP' in pkt:
                try:
                    flags = int(pkt.tcp.flags, 16)
                    if flags & 0x29 == 0x29:
                        msg = f"[HEURÍSTICA] Patrón tipo Xmas Scan detectado desde {pkt.ip.src}"
                        self.mensajes_recientes.append(msg)
                except:
                    pass

            if proto in ['TCP', 'UDP']:
                try:
                    if int(pkt[proto].dstport) == 0:
                        msg = f"[HEURÍSTICA] Puerto destino 0 detectado desde {pkt.ip.src}"
                        self.mensajes_recientes.append(msg)
                except:
                    pass

            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst
            src_port = int(pkt[proto].srcport) if proto in ['TCP', 'UDP'] else 0
            dst_port = int(pkt[proto].dstport) if proto in ['TCP', 'UDP'] else 0
            clave = (ip_src, ip_dst, src_port, dst_port, proto)

            if self.flujos[clave] is None:
                self.flujos[clave] = Flujo(clave)
            self.flujos[clave].agregar(pkt)

            if len(self.flujos[clave].paquetes) >= 20:
                vector = self.flujos[clave].calcular_vector()
                if vector is not None and self.modelo:
                    pred = self.modelo.predict(vector)
                    if pred[0] == 0:
                        msg = f"[ML] 🚨 Amenaza detectada en flujo {clave}"
                        self.mensajes_recientes.append(msg)
                del self.flujos[clave]
        except:
            pass


    def detectar_syn_flood(self, pkt):
       try:
          if 'TCP' not in pkt:
             return False, ""

          flags = int(pkt.tcp.flags, 16)
        # solo SYN sin ACK, FIN ni RST
          if flags == 0x02:
            ip_src = pkt.ip.src
            ahora = datetime.now()
            self.syn_por_ip[ip_src].append(ahora)

            # limpiar entradas viejas
            while self.syn_por_ip[ip_src] and ahora - self.syn_por_ip[ip_src][0] > self.ventana_tiempo:
                self.syn_por_ip[ip_src].popleft()

            if len(self.syn_por_ip[ip_src]) >= self.limite_syn:
                return True, f"SYN Flood detectado desde {ip_src} (más de {self.limite_syn} SYNs en {self.ventana_tiempo.seconds}s)"
       except:
          pass
       return False, ""

    def analizar_archivo(self, archivo_pcap):
        self.mensajes_mostrados.clear()
        self.alertas.clear()
        self.conteo_ips.clear()  # ← Reinicia el conteo al iniciar nuevo análisis
        try:
            cap = pyshark.FileCapture(archivo_pcap)
        except Exception as e:
            self.alertas.append(f"[ERROR] No se pudo abrir el archivo: {e}")
            return

        for pkt in cap:
            if 'IP' not in pkt:
                continue
            try:
                ip_src = pkt.ip.src
                self.conteo_ips[ip_src] += 1  # siempre contar IP origen

                # Heurística: Tráfico HTTP
                if 'HTTP' in pkt:
                    msg = "[HEURÍSTICA] Tráfico HTTP detectado"
                    if msg not in self.mensajes_mostrados:
                        self.alertas.append(msg)
                        self.mensajes_mostrados.add(msg)

                # Heurística: Protocolo inusual
                proto = pkt.transport_layer if hasattr(pkt, 'transport_layer') else 'OTHE'
                if proto not in ['TCP', 'UDP', 'ICMP'] and proto != 'OTHER':
                    msg = f"[HEURÍSTICA] Protocolo inusual: {proto}"
                    if msg not in self.mensajes_mostrados:
                        self.alertas.append(msg)
                        self.mensajes_mostrados.add(msg)

                # Heurística: TTL bajo
                if hasattr(pkt.ip, 'ttl') and int(pkt.ip.ttl) <= 1:
                    msg = f"[HEURÍSTICA] TTL muy bajo: {pkt.ip.ttl}"
                    if msg not in self.mensajes_mostrados:
                        self.alertas.append(msg)
                        self.mensajes_mostrados.add(msg)

                # Heurística: Tráfico TELNET
                es_telnet = (
                   proto == "TCP" and (
                      pkt[proto].dstport == "23" or  # Comparación directa con puerto 23
                      (hasattr(pkt, 'layers') and 'TELNET' in pkt.layers)
                   )
                )
                if es_telnet:
                   msg = "[HEURÍSTICA] Tráfico TELNET detectado"
                   if msg not in self.mensajes_mostrados:
                      self.alertas.append(msg)
                      self.mensajes_mostrados.add(msg)

                # Heurística: DNS nombre sospechoso
                if 'DNS' in pkt:
                    try:
                        nombre = pkt.dns.qry_name
                        if len(nombre) > 100:
                            msg = f"[HEURÍSTICA] Consulta DNS sospechosa/larga: {nombre[:60]}..."
                            if msg not in self.mensajes_mostrados:
                                self.alertas.append(msg)
                                self.mensajes_mostrados.add(msg)
                    except:
                        pass

                # Heurística: MDNS masivo (experimental - detección básica)
                if pkt.highest_layer == "MDNS":
                    msg = f"[HEURÍSTICA] Tráfico MDNS detectado desde {ip_src}"
                    if msg not in self.mensajes_mostrados:
                        self.alertas.append(msg)
                        self.mensajes_mostrados.add(msg)

                # Heurística: Xmas Scan (Nmap)
                if 'TCP' in pkt:
                    try:
                        flags = int(pkt.tcp.flags, 16)
                        if flags & 0x29 == 0x29:
                            msg = f"[HEURÍSTICA] Patrón tipo Xmas Scan detectado desde {ip_src}"
                            if msg not in self.mensajes_mostrados:
                                self.alertas.append(msg)
                                self.mensajes_mostrados.add(msg)
                    except:
                        pass

                # Heurística: Puerto destino 0
                if proto in ['TCP', 'UDP']:
                    try:
                        if int(pkt[proto].dstport) == 0:
                            msg = f"[HEURÍSTICA] Puerto destino 0 detectado desde {ip_src}"
                            if msg not in self.mensajes_mostrados:
                                self.alertas.append(msg)
                                self.mensajes_mostrados.add(msg)
                    except:
                        pass

                ip_dst = pkt.ip.dst
                src_port = int(pkt[proto].srcport) if proto in ['TCP', 'UDP'] else 0
                dst_port = int(pkt[proto].dstport) if proto in ['TCP', 'UDP'] else 0
                clave = (ip_src, ip_dst, src_port, dst_port, proto)

                if self.flujos[clave] is None:
                    self.flujos[clave] = Flujo(clave)
                self.flujos[clave].agregar(pkt)

                if len(self.flujos[clave].paquetes) >= 20:
                    vector = self.flujos[clave].calcular_vector()
                    if vector is not None and self.modelo:
                        pred = self.modelo.predict(vector)
                        if pred[0] == 0:
                            alerta_ml = f"[ML] 🚨 Amenaza detectada en flujo {clave}"
                            if alerta_ml not in self.mensajes_mostrados:
                                self.alertas.append(alerta_ml)
                                self.mensajes_mostrados.add(alerta_ml)
                    del self.flujos[clave]
            except:
                continue
        cap.close()
        self.flujos.clear()

        # Agregar resumen de IPs más activas
        resumen_ips = "\n📊 IPs más activas:"
        if resumen_ips not in self.mensajes_mostrados:
            self.alertas.append(resumen_ips)
            self.mensajes_mostrados.add(resumen_ips)

        if not self.conteo_ips:
            msg = "No se detectaron IPs activas."
            if msg not in self.mensajes_mostrados:
                self.alertas.append(msg)
                self.mensajes_mostrados.add(msg)
        else:
            top_ips = sorted(self.conteo_ips.items(), key=lambda x: x[1], reverse=True)[:5]
            for ip, count in top_ips:
                linea = f"{ip} → {count} paquetes"
                if linea not in self.mensajes_mostrados:
                    self.alertas.append(linea)
                    self.mensajes_mostrados.add(linea)

        print("\n📌 RESUMEN DE ALERTAS:")
        for alerta in self.alertas:
            print(alerta)

        return self.alertas



