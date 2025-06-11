import pyshark
from collections import defaultdict, Counter

class AnalizadorVulnerabilidades:
    def __init__(self, archivo_pcap):
        self.archivo_pcap = archivo_pcap
        try:
        self.cap = pyshark.FileCapture(self.archivo_pcap)
        except Exception as e:
        print(f"[ERROR] No se pudo abrir el archivo: {e}")
        return
        self.conteo_ips = defaultdict(int)
        self.mac_por_ip = defaultdict(set)
        self.dominios_dns = defaultdict(set)
        self.timestamps_por_ip = defaultdict(list)

    def analizar_paquetes(self):
        if not self.cap:
           print("Análisis cancelado: No se pudo cargar la captura.")
           return
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
                    print(f"HTTP sin cifrado: {pkt.ip.src} → {pkt.ip.dst}")
                    if hasattr(pkt.http, 'authorization'):
                        print(f"Credenciales HTTP: {pkt.http.authorization}")

                if 'TCP' in pkt and int(pkt.tcp.flags, 16) == 0:
                    print(f"TCP NULL scan: {pkt.ip.src} → {pkt.ip.dst}")

                if 'TCP' in pkt and int(pkt.tcp.flags, 16) == 1:
                    print(f"TCP FIN scan: {pkt.ip.src} → {pkt.ip.dst}")

                if 'TCP' in pkt and int(pkt.tcp.flags, 16) == 41:
                    print(f"TCP XMAS scan detectado: {pkt.ip.src} → {pkt.ip.dst}")

                if 'IP' in pkt and int(pkt.ip.ttl) < 5:
                    print(f"TTL extremadamente bajo (posible manipulación): {pkt.ip.src}")

                if hasattr(pkt, 'length') and int(pkt.length) > 1500:
                    print(f"Paquete muy grande: {pkt.ip.src} ({pkt.length} bytes)")

                if 'FTP' in pkt:
                    print(f"Tráfico FTP detectado: {pkt.ip.src} → {pkt.ip.dst}")
                    if hasattr(pkt.ftp, 'request_command') and 'USER' in pkt.ftp.request_command:
                        print(f"Usuario FTP enviado: {pkt.ftp.request_arg}")

                if 'TELNET' in pkt:
                    print(f"Tráfico TELNET inseguro: {pkt.ip.src} → {pkt.ip.dst}")

                if 'DNS' in pkt and hasattr(pkt.dns, 'a') and hasattr(pkt.dns, 'qry_name'):
                   if pkt.dns.qry_name.endswith("google.com") and pkt.dns.a != '8.8.8.8':
                      print(f"DNS spoofing sospechoso: {pkt.ip.src} → {pkt.dns.a} para {pkt.dns.qry_name}")

                if 'DNS' in pkt and hasattr(pkt.dns, 'qry_name'):
                    dominio = pkt.dns.qry_name
                    self.dominios_dns[pkt.ip.src].add(dominio)
                    if not hasattr(pkt.dns, 'a'):
                        print(f"Petición DNS sin respuesta: {pkt.ip.src} pidió {dominio}")

                if 'ARP' in pkt:
                    ip = pkt.arp.psrc
                    mac = pkt.arp.hwsrc
                    self.mac_por_ip[ip].add(mac)
                    if len(self.mac_por_ip[ip]) > 1:
                        print(f"ARP Spoofing: {ip} tiene múltiples MACs: {self.mac_por_ip[ip]}")

                if 'HTTP' in pkt and hasattr(pkt.http, 'request_uri'):
                    uri = pkt.http.request_uri.lower()
                    patrones_inyeccion = ["'", "--", "<script>", "or 1=1", "drop table"]
                    if any(p in uri for p in patrones_inyeccion):
                      print(f"Posible inyección detectada desde {pkt.ip.src}: URI sospechosa → {uri}")
                if 'HTTP' in pkt and hasattr(pkt.http, 'response_code'):
                  if pkt.http.response_code in ['401', '403', '500']:
                    print(f"Respuesta HTTP sospechosa desde {pkt.ip.src}: código {pkt.http.response_code}")
            except AttributeError:
                continue

        self.detectar_dns_tunneling()
        self.detectar_dos_simples()
        self.cap.close()

    def detectar_dns_tunneling(self):
        print("\nAnálisis de posibles DNS tunneling:")
        for ip, dominios in self.dominios_dns.items():
            if len(dominios) > 15:
                print(f"Posible DNS tunneling desde {ip}: {len(dominios)} dominios únicos en el tráfico")

    def detectar_dos_simples(self):
        print("\n Detección de actividad DoS sospechosa:")
        for ip, tiempos in self.timestamps_por_ip.items():
            if len(tiempos) >= 10:
                tiempos.sort()
                intervalo = (tiempos[-1] - tiempos[0]).total_seconds()
                if intervalo < 5:
                    print(f"Posible ataque DoS: {ip} envió {len(tiempos)} paquetes en {intervalo:.2f} segundos")

    def mostrar_ips_activas(self):
        print("\n IPs más activas:")
        for ip, count in sorted(self.conteo_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"{ip} → {count} paquetes")

if __name__ == "__main__":
    analizador = AnalizadorVulnerabilidades('paquetes_capturados.pcap')
    analizador.analizar_paquetes()
    analizador.mostrar_ips_activas()

