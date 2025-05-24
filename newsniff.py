import threading
import platform
import os
import time
from tkinter import (
    Tk, Label, Entry, Button, StringVar, messagebox, Text, Scrollbar,
    END, RIGHT, Y, LEFT, BOTH, OptionMenu, Frame, Menu
)
from tkinter import ttk
from scapy.all import (
    sniff, Ether, IP, IPv6, TCP, UDP, wrpcap, get_working_ifaces
)
import pyshark

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
    def __init__(self, iface=None, packet_callback=None, bpf_filter=None):
        self.iface = iface
        self.paquetes_capturados = []
        self.paquetes_raw = []
        self.capturando = False
        self.captura_thread = None
        self.packet_callback = packet_callback
        self.bpf_filter = bpf_filter

    def start(self, tiempo_captura):
        if self.capturando:
            return
        self.capturando = True
        self.paquetes_capturados = []
        self.paquetes_raw = []

        self.captura_thread = threading.Thread(
            target=self._capturar_paquetes, args=(tiempo_captura,), daemon=True)
        self.captura_thread.start()

        if self.packet_callback:
            threading.Thread(target=self._progreso_captura, args=(tiempo_captura,), daemon=True).start()

    def _capturar_paquetes(self, tiempo_captura):
        try:
            sniff(
                prn=self.process_packet,
                store=False,
                iface=self.iface,
                timeout=tiempo_captura,
                filter=self.bpf_filter
            )
        except Exception as e:
            print(f"[ERROR] Error durante la captura: {e}")
        self.stop()

    def _progreso_captura(self, tiempo_captura):
        for t in range(tiempo_captura):
            if not self.capturando:
                break
            progreso = int((t + 1) / tiempo_captura * 100)
            self.packet_callback(f"[Progreso] {tiempo_captura - t}s restantes...")
            self.packet_callback("__PROGRESO__" + str(progreso))
            time.sleep(1)

    def stop(self):
        if self.capturando:
            self.capturando = False
            self.guardar_paquetes()

    def process_packet(self, packet):
        if Ether in packet:
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
            print("[INFO] ¡Paquetes guardados en 'paquetes_capturados.pcap'!")
        else:
            print("[INFO] No se capturaron paquetes.")

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sniffer de Red Mejorado")
        self.root.geometry("800x550")

        self.tema_oscuro = True
        self.set_tema()

        menubar = Menu(root)
        tema_menu = Menu(menubar, tearoff=0)
        tema_menu.add_command(label="Alternar Tema", command=self.toggle_tema)
        menubar.add_cascade(label="Opciones", menu=tema_menu)
        root.config(menu=menubar)

        Label(root, text=f"Sistema Operativo: {platform.system()}", bg=self.bg_color, fg=self.fg_color).pack()

        frame_config = Frame(root, bg=self.bg_color)
        frame_config.pack(pady=10)

        Label(frame_config, text="Interfaz de red:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, sticky='e')
        self.ifaces_dict = {f"{iface.description} ({iface.name})": iface.name for iface in get_working_ifaces()}
        self.iface_var = StringVar(value=list(self.ifaces_dict.keys())[0])
        OptionMenu(frame_config, self.iface_var, *self.ifaces_dict.keys()).grid(row=0, column=1)

        Label(frame_config, text="Tiempo (s):", bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, sticky='e')
        self.tiempo_var = StringVar(value="10")
        Entry(frame_config, textvariable=self.tiempo_var, width=10).grid(row=1, column=1)

        Label(frame_config, text="Filtro BPF:", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, sticky='e')
        self.filtro_var = StringVar()
        Entry(frame_config, textvariable=self.filtro_var, width=30).grid(row=2, column=1)

        Button(root, text="Iniciar Captura", command=self.iniciar_captura, bg="#4CAF50", fg="white").pack(pady=5)
        Button(root, text="Detener Captura", command=self.detener_captura, bg="#F44336", fg="white").pack(pady=5)
        Button(root, text="Analizar con PyShark + IA", command=self.analizar_pcap, bg="#2196F3", fg="white").pack(pady=5)

        self.progress = ttk.Progressbar(root, length=400, mode='determinate')
        self.progress.pack(pady=5)

        self.status_label = Label(root, text="", bg=self.bg_color, fg=self.fg_color)
        self.status_label.pack()

        self.text_area = Text(root, height=15, wrap='none', bg=self.bg_color, fg=self.fg_color, insertbackground=self.fg_color)
        self.text_area.pack(side=LEFT, fill=BOTH, expand=True)

        scrollbar = Scrollbar(root, command=self.text_area.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.text_area.configure(yscrollcommand=scrollbar.set)

        self.sniffer = None

    def set_tema(self):
        self.bg_color = "#000000" if self.tema_oscuro else "#f0f0f0"
        self.fg_color = "lime" if self.tema_oscuro else "black"
        style = ttk.Style()
        style.theme_use('default')
        style.configure("TProgressbar", troughcolor=self.bg_color, background="#00ff00" if self.tema_oscuro else "#2196F3")

    def toggle_tema(self):
        self.tema_oscuro = not self.tema_oscuro
        self.root.destroy()
        nuevo_root = Tk()
        app = SnifferGUI(nuevo_root)
        nuevo_root.mainloop()

    def iniciar_captura(self):
        self.text_area.delete(1.0, END)
        self.progress['value'] = 0
        self.status_label.config(text="")
        tiempo_str = self.tiempo_var.get()
        filtro = self.filtro_var.get()
        iface_name = self.ifaces_dict[self.iface_var.get()]

        try:
            tiempo = int(tiempo_str.strip()) if tiempo_str.strip() else 10
            self.sniffer = PacketSniffer(iface=iface_name, packet_callback=self.mostrar_paquete, bpf_filter=filtro if filtro.strip() else None)
            self.sniffer.start(tiempo)
        except ValueError:
            messagebox.showerror("Error", "Introduce un número válido para el tiempo.")

    def detener_captura(self):
        if self.sniffer:
            self.sniffer.stop()

    def mostrar_paquete(self, resumen):
        if resumen.startswith("__PROGRESO__"):
            valor = int(resumen.replace("__PROGRESO__", ""))
            self.progress['value'] = valor
            self.status_label.config(text=f"Captura en progreso... {valor}%")
            return

        self.text_area.insert(END, resumen + '\n')
        self.text_area.see(END)

    def analizar_pcap(self):
        self.text_area.insert(END, "\n[INFO] Analizando archivo .pcap con PyShark...\n")
        try:
            cap = pyshark.FileCapture("paquetes_capturados.pcap", only_summaries=True)
            resumenes = [pkt.summary_line for pkt in cap]
            cap.close()
            for r in resumenes:
                self.text_area.insert(END, r + '\n')

            recomendaciones = self.analisis_ai(resumenes)
            self.text_area.insert(END, "\n[IA] Recomendaciones de seguridad:\n")
            for r in recomendaciones:
                self.text_area.insert(END, f"- {r}\n")
        except Exception as e:
            self.text_area.insert(END, f"[ERROR] Error al analizar: {e}\n")

    def analisis_ai(self, resumenes):
        recomendaciones = []
        for linea in resumenes:
            if "TCP" in linea and "80" in linea:
                recomendaciones.append("Se detectó tráfico HTTP. Considera usar HTTPS para mayor seguridad.")
            elif "UDP" in linea and "53" in linea:
                recomendaciones.append("Tráfico DNS detectado. Revisa si se está usando DNS seguro (DoH o DoT).")
            elif "Telnet" in linea:
                recomendaciones.append("Se detectó tráfico Telnet. Considera reemplazarlo por SSH, ya que Telnet no es seguro.")
        if not recomendaciones:
            recomendaciones.append("No se detectaron vulnerabilidades comunes.")
        return recomendaciones

if __name__ == "__main__":
    os.system("cls" if platform.system() == "Windows" else "clear")
    root = Tk()
    app = SnifferGUI(root)
    root.mainloop()
