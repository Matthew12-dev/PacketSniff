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
import socket
import json
import argparse
from scapy.all import sniff, Ether, IP, TCP, UDP

class Paquete:
    def __init__(self, dest_mac, src_mac, eth_proto, trans_proto=None, src_port=None, dest_port=None):
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.eth_proto = eth_proto
        self.trans_proto = trans_proto
        self.src_port = src_port
        self.dest_port = dest_port

    def mostrar_info(self):
        print('\nEthernet Frame:')
        print(f'Destino: {self.dest_mac}, Origen: {self.src_mac}, Protocolo Ethernet: {self.eth_proto}')
        if self.trans_proto:
            print(f'Protocolo de Transporte: {self.trans_proto}')
            if self.src_port is not None and self.dest_port is not None:
                print(f'Puerto Origen: {self.src_port}, Puerto Destino: {self.dest_port}')

    def to_dict(self):
        data = {
            'dest_mac': self.dest_mac,
            'src_mac': self.src_mac,
            'eth_proto': self.eth_proto,
            'trans_proto': self.trans_proto
        }
        if self.src_port is not None and self.dest_port is not None:
            data['src_port'] = self.src_port
            data['dest_port'] = self.dest_port
        return data

class PacketSniffer:
    def __init__(self, iface=None):
        self.iface = iface
        self.paquetes_capturados = []

    def start(self, tiempo_captura):
        print(f"Capturando paquetes durante {tiempo_captura} segundos...")
        sniff(prn=self.process_packet, store=False, iface=self.iface, timeout=tiempo_captura)
        print("\nCaptura terminada. Guardando paquetes en JSON...")
        self.guardar_paquetes()

    def process_packet(self, packet):
        if Ether in packet:
            paquete = self.parse_ethernet_frame(packet)
            if paquete:
                paquete.mostrar_info()
                self.paquetes_capturados.append(paquete)

    def parse_ethernet_frame(self, packet):
        eth = packet[Ether]
        dest_mac = eth.dst.upper()
        src_mac = eth.src.upper()
        eth_proto = eth.type

        trans_proto = None
        src_port = None
        dest_port = None

        if eth_proto == 0x0800 and IP in packet:
            ip_layer = packet[IP]
            proto_num = ip_layer.proto

            if proto_num == 6 and TCP in packet:
                trans_proto = 'TCP'
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dest_port = tcp_layer.dport
            elif proto_num == 17 and UDP in packet:
                trans_proto = 'UDP'
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dest_port = udp_layer.dport
            else:
                trans_proto = f'Otro (Protocolo {proto_num})'

        return Paquete(dest_mac, src_mac, eth_proto, trans_proto, src_port, dest_port)

    def guardar_paquetes(self):
        lista_dicts = [paquete.to_dict() for paquete in self.paquetes_capturados]
        with open('paquetes_capturados.json', 'w') as f:
            json.dump(lista_dicts, f, indent=4)
        print("¡Paquetes guardados en 'paquetes_capturados.json'!")

def main():
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer con tiempo de captura")
    parser.add_argument('-t', '--tiempo', type=int, default=10, help="Tiempo de captura en segundos (por defecto 10s)")
    args = parser.parse_args()

    sniffer = PacketSniffer()
    sniffer.start(tiempo_captura=args.tiempo)

if __name__ == "__main__":
    main()

