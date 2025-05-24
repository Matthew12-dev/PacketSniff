import threading
from tkinter import Tk, Label, Entry, Button, StringVar, messagebox, Text, Scrollbar, END, RIGHT, Y, LEFT, BOTH
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, wrpcap


class Paquete:
    def __init__(self, dest_mac, src_mac, eth_proto, trans_proto=None,
                 src_port=None, dest_port=None, ip_src=None, ip_dst=None, ip_version=None):
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.eth_proto = eth_proto
        self.trans_proto = trans_proto
        self.src_port = src_port
        self.dest_port = dest_port
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.ip_version = ip_version

    def resumen(self):
        info = f"Ethernet: {self.src_mac} -> {self.dest_mac} | Proto: {hex(self.eth_proto)}"
        if self.ip_version:
            info += f" | IPv{self.ip_version}: {self.ip_src} -> {self.ip_dst}"
        if self.trans_proto:
            info += f" | {self.trans_proto}"
            if self.src_port is not None and self.dest_port is not None:
                info += f" {self.src_port} -> {self.dest_port}"
        return info


class PacketSniffer:
    def __init__(self, iface=None, packet_callback=None):
        self.iface = iface
        self.paquetes_capturados = []
        self.paquetes_raw = []
        self.capturando = False
        self.captura_thread = None
        self.packet_callback = packet_callback

    def start(self, tiempo_captura):
        if self.capturando:
            return
        self.capturando = True
        self.paquetes_capturados = []
        self.paquetes_raw = []
        print(f"Capturando paquetes durante {tiempo_captura} segundos...")

        self.captura_thread = threading.Thread(target=self._capturar_paquetes,args=(tiempo_captura,),daemon=True)
        self.captura_thread.start()

    def _capturar_paquetes(self, tiempo_captura):
        sniff(
            prn=self.process_packet,
            store=False,
            iface=self.iface,
            timeout=tiempo_captura,
            stop_filter=lambda x: not self.capturando
        )
        self.stop()

    def stop(self):
        if self.capturando:
            self.capturando = False
            print("Captura terminada. Guardando en archivo .pcap...")
            self.guardar_paquetes()

    def process_packet(self, packet):
        if Ether in packet and self.capturando:
            eth = packet[Ether]
            dest_mac = eth.dst.upper()
            src_mac = eth.src.upper()
            eth_proto = eth.type

            trans_proto = None
            src_port = None
            dest_port = None
            ip_src = None
            ip_dst = None
            ip_version = None

            if IP in packet:
                ip_layer = packet[IP]
                ip_src = ip_layer.src
                ip_dst = ip_layer.dst
                ip_version = 4
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

            elif IPv6 in packet:
                ipv6_layer = packet[IPv6]
                ip_src = ipv6_layer.src
                ip_dst = ipv6_layer.dst
                ip_version = 6

                if TCP in packet:
                    trans_proto = 'TCP'
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dest_port = tcp_layer.dport
                elif UDP in packet:
                    trans_proto = 'UDP'
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dest_port = udp_layer.dport

            paquete = Paquete(dest_mac, src_mac, eth_proto, trans_proto, src_port, dest_port,
                              ip_src, ip_dst, ip_version)
            self.paquetes_capturados.append(paquete)
            self.paquetes_raw.append(packet)
            if self.packet_callback:
                self.packet_callback(paquete.resumen())

    def guardar_paquetes(self):
        if self.paquetes_raw:
            wrpcap("paquetes_capturados.pcap", self.paquetes_raw)
            print("¡Paquetes guardados en 'paquetes_capturados.pcap'!")
        else:
            print("No se capturaron paquetes.")


class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sniffer de Red")

        Label(root, text="Tiempo de captura (segundos):").pack()
        self.tiempo_var = StringVar()
        Entry(root, textvariable=self.tiempo_var).pack()

        Button(root, text="Iniciar Captura", command=self.iniciar_captura).pack(pady=5)
        Button(root, text="Detener Captura", command=self.detener_captura).pack(pady=5)

        self.text_area = Text(root, height=15, wrap='none')
        self.text_area.pack(side=LEFT, fill=BOTH, expand=True)

        scrollbar = Scrollbar(root, command=self.text_area.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.text_area.configure(yscrollcommand=scrollbar.set)

        self.sniffer = PacketSniffer(packet_callback=self.mostrar_paquete)

    def iniciar_captura(self):
        self.text_area.delete(1.0, END)
        tiempo_str = self.tiempo_var.get()
        try:
            tiempo = int(tiempo_str) if tiempo_str.strip() else 10
            self.sniffer.start(tiempo)
        except ValueError:
            messagebox.showerror("Error", "Por favor, introduce un número válido.")

    def detener_captura(self):
        self.sniffer.stop()

    def mostrar_paquete(self, resumen):
        self.text_area.insert(END, resumen + '\n')
        self.text_area.see(END)


if __name__ == "__main__":
    root = Tk()
    app = SnifferGUI(root)
    root.mainloop()
