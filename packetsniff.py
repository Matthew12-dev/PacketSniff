import socket, argparse, sys

class GestorSistema:
  pass

from scapy.all import sniff, Ether

class PacketSniffer:
    def __init__(self, iface=None):
        self.iface = iface  # Puedes especificar la interfaz si quieres

    def start(self):
        print("Capturando paquetes... (Presiona Ctrl+C para detener)")
        sniff(prn=self.process_packet, store=False, iface=self.iface)

    def process_packet(self, packet):
        if Ether in packet:
            dest_mac, src_mac, eth_proto = self.parse_ethernet_frame(packet)
            print('\nEthernet Frame:')
            print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

    def parse_ethernet_frame(self, packet):
        eth = packet[Ether]
        dest_mac = eth.dst.upper()
        src_mac = eth.src.upper()
        eth_proto = eth.type  # Protocolo Ethernet
        return dest_mac, src_mac, eth_proto

class Analizador:
  pass

class GeneradorReportesIA:
  pass

def main():
  sniffer = PacketSniffer()
  sniffer.start()

main()
