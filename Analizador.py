import pyshark
from collections import defaultdict, Counter

class AnalizadorVulnerabilidades:
    def __init__(self, archivo_pcap):
        self.archivo_pcap = archivo_pcap
        self.alertas = []
        try:
            self.cap = pyshark.FileCapture(self.archivo_pcap)
        except Exception as e:
            print(f"[ERROR] No se pudo abrir el archivo: {e}")
            self.cap = []
        self.conteo_ips = defaultdict(int)
        self.mac_por_ip = defaultdict(set)
        self.dominios_dns = defaultdict(set)
        self.timestamps_por_ip = defaultdict(list)

    def analizar_paquetes(self):
        print("\nIniciando análisis de posibles vulnerabilidades...\n")
        for pkt in self.cap:
            try:
                if 'IP' in pkt:
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                    self.conteo_ips[src] += 1
                    if hasattr(pkt, 'sniff_time'):
                        self.timestamps_por_ip[src].append(pkt.sniff_time)

                if 'HTTP' in pkt:
                    msg = f"HTTP sin cifrado: {pkt.ip.src} → {pkt.ip.dst}"
                    self.alertas.append(msg)
                    if hasattr(pkt.http, 'authorization'):
                        cred = f"Credenciales HTTP expuestas: {pkt.http.authorization}"
                        self.alertas.append(cred)

                flags = getattr(pkt.tcp, 'flags', None) if 'TCP' in pkt else None
                if flags:
                    flag_val = int(flags, 16)
                    if flag_val == 0:
                        self.alertas.append(f"TCP NULL scan detectado: {pkt.ip.src} → {pkt.ip.dst}")
                    elif flag_val == 1:
                        self.alertas.append(f"TCP FIN scan detectado: {pkt.ip.src} → {pkt.ip.dst}")
                    elif flag_val == 41:
                        self.alertas.append(f"TCP XMAS scan detectado: {pkt.ip.src} → {pkt.ip.dst}")

                if 'IP' in pkt and int(pkt.ip.ttl) < 5:
                    self.alertas.append(f"TTL extremadamente bajo (posible manipulación): {pkt.ip.src} TTL={pkt.ip.ttl}")

                if hasattr(pkt, 'length') and int(pkt.length) > 1500:
                    self.alertas.append(f"Paquete muy grande: {pkt.ip.src} ({pkt.length} bytes)")

                if 'FTP' in pkt:
                    self.alertas.append(f"Tráfico FTP detectado: {pkt.ip.src} → {pkt.ip.dst}")
                    if hasattr(pkt.ftp, 'request_command') and 'USER' in pkt.ftp.request_command:
                        self.alertas.append(f"Usuario FTP enviado: {pkt.ftp.request_arg}")

                if 'TELNET' in pkt:
                    self.alertas.append(f"Tráfico TELNET inseguro: {pkt.ip.src} → {pkt.ip.dst}")

                if 'DNS' in pkt and hasattr(pkt.dns, 'qry_name'):
                    dominio = pkt.dns.qry_name
                    src_ip = pkt.ip.src
                    self.dominios_dns[src_ip].add(dominio)
                    if not hasattr(pkt.dns, 'a'):
                        self.alertas.append(f"Petición DNS sin respuesta: {src_ip} pidió {dominio}")
                    elif dominio.endswith("google.com") and pkt.dns.a != "8.8.8.8":
                        self.alertas.append(f"DNS spoofing sospechoso: {src_ip} devolvió {pkt.dns.a} para {dominio}")

                if 'ARP' in pkt:
                    ip = pkt.arp.psrc
                    mac = pkt.arp.hwsrc
                    self.mac_por_ip[ip].add(mac)
                    if len(self.mac_por_ip[ip]) > 1:
                        self.alertas.append(f"ARP Spoofing: {ip} tiene múltiples MACs: {self.mac_por_ip[ip]}")

                if 'HTTP' in pkt and hasattr(pkt.http, 'request_uri'):
                    uri = pkt.http.request_uri.lower()
                    patrones_inyeccion = ["'", "--", "<script>", "or 1=1", "drop table"]
                    if any(p in uri for p in patrones_inyeccion):
                        self.alertas.append(f"Inyección sospechosa desde {pkt.ip.src}: URI → {uri}")

                if 'HTTP' in pkt and hasattr(pkt.http, 'response_code'):
                    if pkt.http.response_code in ['401', '403', '500']:
                        self.alertas.append(f"Respuesta HTTP anómala desde {pkt.ip.src}: código {pkt.http.response_code}")

            except AttributeError:
                continue

        self.detectar_dns_tunneling()
        self.detectar_dos_simples()

    def detectar_dns_tunneling(self):
        for ip, dominios in self.dominios_dns.items():
            if len(dominios) > 15:
                self.alertas.append(f"Posible DNS tunneling desde {ip}: {len(dominios)} dominios únicos")

    def detectar_dos_simples(self):
        for ip, tiempos in self.timestamps_por_ip.items():
            if len(tiempos) >= 10:
                tiempos.sort()
                intervalo = (tiempos[-1] - tiempos[0]).total_seconds()
                if intervalo < 5:
                    self.alertas.append(f"Posible ataque DoS: {ip} envió {len(tiempos)} paquetes en {intervalo:.2f} segundos")

    def mostrar_ips_activas(self):
        resumen = sorted(self.conteo_ips.items(), key=lambda x: x[1], reverse=True)[:5]
        print("\n IPs más activas:")
        for ip, count in resumen:
            print(f"{ip} → {count} paquetes")

