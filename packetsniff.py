# import socket, argparse, sys

# class GestorSistema:
#   pass

# from scapy.all import sniff, Ether

# class PacketSniffer:
#     def __init__(self, iface=None):
#         self.iface = iface  # Puedes especificar la interfaz si quieres

#     def start(self):
#         print("Capturando paquetes... (Presiona Ctrl+C para detener)")
#         sniff(prn=self.process_packet, store=False, iface=self.iface)

#     def process_packet(self, packet):
#         if Ether in packet:
#             dest_mac, src_mac, eth_proto = self.parse_ethernet_frame(packet)
#             print('\nEthernet Frame:')
#             print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

#     def parse_ethernet_frame(self, packet):
#         eth = packet[Ether]
#         dest_mac = eth.dst.upper()
#         src_mac = eth.src.upper()
#         eth_proto = eth.type  # Protocolo Ethernet
#         return dest_mac, src_mac, eth_proto

# class Analizador:
#   pass

# class GeneradorReportesIA:
#   pass

# def main():
#   sniffer = PacketSniffer()
#   sniffer.start()

# main()
import argparse
from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, wrpcap

class Paquete:
    def __init__(self, src_mac, dest_mac, eth_proto, trans_proto=None, src_ip=None, dest_ip=None, src_port=None, dest_port=None):
        self.src_mac = src_mac
        self.dest_mac = dest_mac
        self.eth_proto = eth_proto
        self.trans_proto = trans_proto
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port

    def mostrar_info(self):
        print("\nPaquete capturado:")
        print(f"MAC Origen: {self.src_mac}, MAC Destino: {self.dest_mac}, Protocolo Ethernet: {self.eth_proto}")
        if self.trans_proto:
            print(f"Protocolo de Capa 3/4: {self.trans_proto}")
        if self.src_ip and self.dest_ip:
            print(f"IP Origen: {self.src_ip}, IP Destino: {self.dest_ip}")
        if self.src_port is not None and self.dest_port is not None:
            print(f"Puerto Origen: {self.src_port}, Puerto Destino: {self.dest_port}")

class PacketSniffer:
    def __init__(self, iface=None):
        self.iface = iface
        self.paquetes_raw = []  # Para guardar en .pcap
        self.paquetes_analizados = []

    def start(self, tiempo_captura):
        print(f"📡 Capturando tráfico durante {tiempo_captura} segundos...")
        sniff(
            iface=self.iface,
            timeout=tiempo_captura,
            store=False,
            prn=self.process_packet
        )
        print("\nCaptura terminada. Guardando en .pcap...")
        self.guardar_pcap()

    def process_packet(self, packet):
        self.paquetes_raw.append(packet) 

        if Ether in packet:
            eth = packet[Ether]
            dest_mac = eth.dst.upper()
            src_mac = eth.src.upper()
            eth_proto = eth.type

            
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dest_ip = ip_layer.dst
                trans_proto = "IP"
                src_port = None
                dest_port = None

                if TCP in packet:
                    trans_proto = "TCP"
                    src_port = packet[TCP].sport
                    dest_port = packet[TCP].dport
                elif UDP in packet:
                    trans_proto = "UDP"
                    src_port = packet[UDP].sport
                    dest_port = packet[UDP].dport
                elif ip_layer.proto == 1:
                    trans_proto = "ICMP"

                paquete = Paquete(src_mac, dest_mac, eth_proto, trans_proto, src_ip, dest_ip, src_port, dest_port)
                paquete.mostrar_info()
                self.paquetes_analizados.append(paquete)

            
            elif ARP in packet:
                arp_layer = packet[ARP]
                trans_proto = "ARP"
                src_ip = arp_layer.psrc
                dest_ip = arp_layer.pdst

                paquete = Paquete(src_mac, dest_mac, eth_proto, trans_proto, src_ip, dest_ip)
                paquete.mostrar_info()
                self.paquetes_analizados.append(paquete)

    def guardar_pcap(self):
        wrpcap("paquetes_capturados.pcap", self.paquetes_raw)
        print("Archivo 'paquetes_capturados.pcap' guardado correctamente.")

def main():
    parser = argparse.ArgumentParser(description="Sniffer POO con análisis de IP, TCP, UDP, ICMP y ARP")
    parser.add_argument('-t', '--tiempo', type=int, default=10, help="Tiempo de captura en segundos (por defecto 10s)")
    args = parser.parse_args()

    sniffer = PacketSniffer()
    sniffer.start(tiempo_captura=args.tiempo)

if __name__ == "__main__":
    main()

