import customtkinter as ctk
import threading
import os
import time
import platform
from Analizador import AnalizadorVulnerabilidades
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, wrpcap, get_working_ifaces
from tkinter import messagebox, filedialog
import datetime

# Configuración inicial de apariencia
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("dark-blue")

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
    def __init__(self, iface=None, packet_callback=None, bpf_filter=None, ruta_guardado="."):
        self.iface = iface
        self.paquetes_capturados = []
        self.paquetes_raw = []
        self.capturando = False
        self.captura_thread = None
        self.packet_callback = packet_callback
        self.bpf_filter = bpf_filter
        self.tiempo_captura = None
        self.inicio = None
        self.ruta_guardado = ruta_guardado

    def start(self, tiempo_captura):
        if self.capturando:
            return
        self.capturando = True
        self.paquetes_capturados = []
        self.paquetes_raw = []
        self.tiempo_captura = tiempo_captura
        self.inicio = time.time()

        self.captura_thread = threading.Thread(
            target=self._capturar_paquetes, daemon=True)
        self.captura_thread.start()
        if self.packet_callback:
            threading.Thread(target=self._progreso_captura_fluido, daemon=True).start()

    def _capturar_paquetes(self):
        try:
            while self.capturando and (time.time() - self.inicio) < self.tiempo_captura:
                sniff(
                    prn=self.process_packet,
                    store=False,
                    iface=self.iface,
                    filter=self.bpf_filter,
                    count=1,
                    timeout=1
                )
        except Exception as e:
            print(f"[ERROR] Error durante la captura: {e}")
        self.stop()

    def _progreso_captura_fluido(self):
        while self.capturando:
            elapsed = time.time() - self.inicio
            progreso = (elapsed + 1) / self.tiempo_captura
            if progreso >= 1.0:
                self.packet_callback("__PROGRESO__100")
                break
            else:
                self.packet_callback(f"__PROGRESO__{int(progreso * 100)}")
            time.sleep(0.05)

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
            if not os.path.exists(self.ruta_guardado):
                os.makedirs(self.ruta_guardado)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.ruta_guardado, f"captura_{timestamp}.pcap")
            wrpcap(filename, self.paquetes_raw)
            print(f"[INFO] ¡Paquetes guardados en '{filename}'!")
        else:
            print("[INFO] No se capturaron paquetes.")

class SnifferGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Sniffer de Red Mejorado")
        self.geometry("850x750")
        self.sniffer = None

        self.tema_oscuro = ctk.BooleanVar(value=True)
        self.ruta_guardado_var = ctk.StringVar(value=os.path.abspath("capturas"))
        self.crear_componentes()

    def crear_componentes(self):
        # ======== INFO DEL SISTEMA Y CONFIG ========
        frame_config = ctk.CTkFrame(self)
        frame_config.pack(pady=10, padx=10, fill="x")

        ctk.CTkLabel(frame_config, text=f"Sistema Operativo: {platform.system()}").pack(anchor="w", pady=2)

        self.ifaces_dict = {f"{iface.description} ({iface.name})": iface.name for iface in get_working_ifaces()}
        self.iface_var = ctk.StringVar(value=list(self.ifaces_dict.keys())[0])
        self.filtro_var = ctk.StringVar()

        frame_cols = ctk.CTkFrame(frame_config)
        frame_cols.pack(fill="x", pady=5)

        # Columna izquierda: Interfaz de red
        frame_left = ctk.CTkFrame(frame_cols)
        frame_left.pack(side="left", expand=True, fill="both", padx=(0, 5))
        ctk.CTkLabel(frame_left, text="Interfaz de red:").pack(anchor="w")
        self.iface_menu = ctk.CTkOptionMenu(frame_left, variable=self.iface_var, values=list(self.ifaces_dict.keys()))
        self.iface_menu.pack(fill="x")

        # Columna derecha: Filtro BPF
        frame_right = ctk.CTkFrame(frame_cols)
        frame_right.pack(side="left", expand=True, fill="both", padx=(5, 0))
        ctk.CTkLabel(frame_right, text="Filtro BPF:").pack(anchor="w")
        ctk.CTkEntry(frame_right, textvariable=self.filtro_var).pack(fill="x")

        # ======== PARÁMETROS DE CAPTURA ========
        frame_param = ctk.CTkFrame(self)
        frame_param.pack(pady=10, padx=10, fill="x")

        self.tiempo_var = ctk.StringVar(value="10")
        ctk.CTkLabel(frame_param, text="Tiempo de captura (segundos):").pack(anchor="w")
        ctk.CTkEntry(frame_param, textvariable=self.tiempo_var).pack(fill="x", pady=5)

        # Label superior
        ctk.CTkLabel(frame_param, text="Ruta de guardado:").pack(anchor="w")

        # Frame para entrada y botón
        ruta_frame = ctk.CTkFrame(frame_param)
        ruta_frame.pack(fill="x", pady=5)

        # Configurar columnas (50% para cada elemento)
        ruta_frame.grid_columnconfigure(0, weight=1)  # Columna para la entrada (50%)
        ruta_frame.grid_columnconfigure(1, weight=1)  # Columna para el botón (50%)

        # Entrada (mitad izquierda)
        ctk.CTkEntry(ruta_frame, textvariable=self.ruta_guardado_var).grid(
            row=0, column=0, sticky="ew", padx=(0, 5)  # Margen derecho de 5px
        )

        # Botón (mitad derecha)
        ctk.CTkButton(ruta_frame,text="Abrir carpeta",command=self.abrir_carpeta,width=120).grid(row=0, column=1, sticky="w") 

        # ======== BOTONES DE CONTROL ========
        frame_botones = ctk.CTkFrame(self)
        frame_botones.pack(pady=10, padx=10, fill="x")
        ctk.CTkButton(frame_botones, text="Iniciar Captura", command=self.iniciar_captura).pack(side="left", expand=True, padx=5)
        ctk.CTkButton(frame_botones, text="Detener Captura", command=self.detener_captura).pack(side="left", expand=True, padx=5)
        ctk.CTkButton(frame_botones, text="Analizar con PyShark", command=self.analizar_pcap).pack(side="left", expand=True, padx=5)

        # ======== ESTADO Y PROGRESO ========
        frame_estado = ctk.CTkFrame(self)
        frame_estado.pack(pady=10, padx=10, fill="x")

        self.progress = ctk.CTkProgressBar(frame_estado)
        self.progress.set(0)
        self.progress.pack(fill="x", pady=5)

        self.label_estado = ctk.CTkLabel(frame_estado, text="")
        self.label_estado.pack()

        self.switch_tema = ctk.CTkSwitch(frame_estado, text="Modo Oscuro", variable=self.tema_oscuro, command=self.toggle_tema)
        self.switch_tema.select()
        self.switch_tema.pack(pady=5)

        # ======== ÁREA DE RESULTADOS ========
        self.text_area = ctk.CTkTextbox(self, height=15)
        self.text_area.pack(fill="both", expand=True, padx=10, pady=10)
        self.text_area.tag_config("warning", foreground="red")

    def iniciar_captura(self):
        self.text_area.delete("1.0", "end")
        self.progress.set(0)
        self.label_estado.configure(text="")

        try:
            tiempo = int(self.tiempo_var.get())
            iface_name = self.ifaces_dict[self.iface_var.get()]
            filtro = self.filtro_var.get().strip() or None
            ruta = self.ruta_guardado_var.get()
            self.sniffer = PacketSniffer(iface=iface_name, packet_callback=self.mostrar_paquete, bpf_filter=filtro, ruta_guardado=ruta)
            self.sniffer.start(tiempo)
        except ValueError:
            messagebox.showerror("Error", "Introduce un número válido para el tiempo.")

    def detener_captura(self):
        if self.sniffer:
            self.sniffer.stop()

    def mostrar_paquete(self, resumen):
        if resumen.startswith("__PROGRESO__"):
            valor = int(resumen.replace("__PROGRESO__", ""))
            self.progress.set(min(valor / 100, 1.0))
            self.label_estado.configure(text=f"Captura en progreso... {valor}%")
        else:
            self.text_area.insert("end", resumen + '\n')
            self.text_area.see("end")

    def analizar_pcap(self):
        ruta = self.ruta_guardado_var.get()
        archivos = sorted([f for f in os.listdir(ruta) if f.endswith(".pcap")])
        if not archivos:
            messagebox.showinfo("Sin archivos", "No hay archivos .pcap en la carpeta de guardado.")
            return
        ultimo = os.path.join(ruta, archivos[-1])
        
        analizador = AnalizadorVulnerabilidades(ultimo)
        self.text_area.insert("end", "\nResultados del análisis:\n", "bold")
        analizador.analizar_paquetes()

        if hasattr(analizador, 'alertas') and analizador.alertas:
            self.text_area.insert("end", "\nAdvertencias detectadas:\n", "warning")
            for alerta in analizador.alertas:
                self.text_area.insert("end", alerta + '\n', "warning")
            messagebox.showwarning("Advertencia de Seguridad", "Se detectaron posibles amenazas.\nRevisa los detalles en el panel.")
        else:
            self.text_area.insert("end", "\nNo se detectaron amenazas evidentes.\n")
            messagebox.showinfo("Análisis completo", "No se encontraron alertas de seguridad.")

        self.text_area.insert("end", "\nIPs más activas:\n", "bold")
        for ip, count in sorted(analizador.conteo_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            self.text_area.insert("end", f"{ip} → {count} paquetes\n")

        self.text_area.see("end")

    def abrir_carpeta(self):
        ruta = self.ruta_guardado_var.get()
        if os.path.exists(ruta):
            if platform.system() == "Windows":
                os.startfile(ruta)
            elif platform.system() == "Darwin":
                os.system(f"open '{ruta}'")
            else:
                os.system(f"xdg-open '{ruta}'")
        else:
            messagebox.showerror("Ruta inválida", "La carpeta especificada no existe.")

    def toggle_tema(self):
        nuevo_modo = "Dark" if self.tema_oscuro.get() else "Light"
        ctk.set_appearance_mode(nuevo_modo)

if __name__ == "__main__":
    app = SnifferGUI()
    app.mainloop()

