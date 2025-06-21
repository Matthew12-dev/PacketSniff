import threading
import os
import time
import platform
from Analizador import AnalizadorVulnerabilidades
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, wrpcap, get_working_ifaces
import customtkinter as ctk
from tkinter import messagebox, filedialog
import datetime



# Configuración inicial de apariencia
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("dark-blue")

PROGRESO_PREFIX = "__PROGRESO__"

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
        self.guardar_paquetes()
        self.stop()

    def _progreso_captura_fluido(self):
        while self.capturando:
            elapsed = time.time() - self.inicio
            progreso = (elapsed + 1) / self.tiempo_captura
            if progreso >= 1.0:
                self.packet_callback(f"{PROGRESO_PREFIX}100")
                break
            else:
                self.packet_callback(f"{PROGRESO_PREFIX}{int(progreso * 100)}")
            time.sleep(0.05)

    def stop(self):
        if self.capturando:
            self.capturando = False
        

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

    def guardar_paquetes(self, nombre_archivo=None):
       if not self.paquetes_raw:
           print("[INFO] No se capturaron paquetes. No se guardó ningún archivo.")
           return

       if not os.path.exists(self.ruta_guardado):
          os.makedirs(self.ruta_guardado)

       timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
       nombre = f"{nombre_archivo}.pcap" if nombre_archivo else f"captura_{timestamp}.pcap"
       filename = os.path.join(self.ruta_guardado, nombre)
       wrpcap(filename, self.paquetes_raw)
       print(f"[INFO] ¡Paquetes guardados en '{filename}'!")


class SnifferGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Sniffer de Red")
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
        self.nombre_archivo_var = ctk.StringVar()

        # Etiqueta de sección
        ctk.CTkLabel(frame_param, text="Configuración Manual").pack(anchor="w")
        frame_param.pack(side="left", expand=True, fill="both", padx=(5, 0))
        

        # Crear fila para tiempo y nombre
        tiempo_nombre_frame = ctk.CTkFrame(frame_param)
        tiempo_nombre_frame.pack(fill="x", pady=5)

        # Configurar columnas para proporción
        tiempo_nombre_frame.grid_columnconfigure(0, weight=1)
        tiempo_nombre_frame.grid_columnconfigure(1, weight=3)

        # Etiquetas
        ctk.CTkLabel(tiempo_nombre_frame, text="Tiempo captura:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        ctk.CTkLabel(tiempo_nombre_frame, text="Nombre del archivo:").grid(row=0, column=1, sticky="w")

        # Campos
        ctk.CTkEntry(tiempo_nombre_frame, textvariable=self.tiempo_var, width=50).grid(
        row=1, column=0, sticky="ew", padx=(0, 5) 
        )
        ctk.CTkEntry(tiempo_nombre_frame, textvariable=self.nombre_archivo_var, placeholder_text="Nombre del archivo (.pcap)").grid(
        row=1, column=1, sticky="ew"
        )

        # Label superior
        ctk.CTkLabel(frame_param, text="Ruta de guardado para el archivo:").pack(anchor="w")

        # Frame para ruta, botón y nombre de archivo
        ruta_frame = ctk.CTkFrame(frame_param)
        ruta_frame.pack(fill="x", pady=5)
        # Variables
        self.nombre_archivo_var = ctk.StringVar()

        # Configurar columnas (ajustadas)
        ruta_frame.grid_columnconfigure(0, weight=2)
        ruta_frame.grid_columnconfigure(1, weight=0)
        ruta_frame.grid_columnconfigure(2, weight=0)


        # Campo de entrada para la ruta
        ctk.CTkEntry(ruta_frame, textvariable=self.ruta_guardado_var).grid(
        row=0, column=0, sticky="ew", padx=(0, 5)
        )

        # Botón para abrir carpeta
        ctk.CTkButton(ruta_frame, text="Abrir carpeta", command=self.abrir_carpeta, width=120).grid(
        row=0, column=1, sticky="w", padx=(0, 5)
        )
                # ======= Análisis manual por ruta de archivo =======
        ctk.CTkLabel(frame_param, text="Analizar archivo pcap existente:").pack(anchor="w")

        analizar_frame = ctk.CTkFrame(frame_param)
        analizar_frame.pack(fill="x", pady=5)

        self.ruta_pcap_manual_var = ctk.StringVar()

        analizar_frame.grid_columnconfigure(0, weight=2)
        analizar_frame.grid_columnconfigure(1, weight=0)

        self.entry_ruta_pcap = ctk.CTkEntry(
            analizar_frame,
            textvariable=self.ruta_pcap_manual_var,
            placeholder_text="Ruta del archivo .pcap"
        )
        self.entry_ruta_pcap.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.entry_ruta_pcap.bind("<Button-1>", self.abrir_dialogo_archivo)

        ctk.CTkButton(analizar_frame, text="Analizar", command=self.analizar_ruta_manual).grid(
            row=0, column=1, sticky="w"
        )

        # ======== BOTONES DE CONTROL ========
        frame_botones = ctk.CTkFrame(self)
        frame_botones.pack(pady=10, padx=10, fill="x")
        ctk.CTkButton(frame_botones, text="Iniciar Captura Manual", command=self.iniciar_captura).pack(side="left", expand=True, padx=5)
        ctk.CTkButton(frame_botones, text="Detener Captura", command=self.detener_captura).pack(side="left", expand=True, padx=5)
        ctk.CTkButton(frame_botones, text="Captura Automatica", command=self.iniciar_captura_manual).pack(side="left", expand=True, padx=5)

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

        # ======== ÁREA DE RESULTADOS (ocultable) ========
        self.frame_resultados = ctk.CTkFrame(self)
        self.frame_resultados.pack(fill="both", expand=True, padx=10, pady=10)

        self.text_area = ctk.CTkTextbox(self.frame_resultados, height=28)
        self.text_area.pack(fill="both", expand=True)
        self.text_area.tag_config("warning", foreground="red")

        # Switch para mostrar/ocultar el contenedor de paquetes
        self.mostrar_paquetes_var = ctk.BooleanVar(value=True)
        self.switch_paquetes = ctk.CTkSwitch(
            self, text="Mostrar paquetes",
            variable=self.mostrar_paquetes_var,
            command=self.toggle_paquetes
)
        # Empaqueta el switch justo debajo de los botones de control (o donde prefieras)
        self.switch_paquetes.pack(pady=5)

        
    def abrir_dialogo_archivo(self, event=None):
        archivo = filedialog.askopenfilename(filetypes=[("Archivos PCAP", "*.pcap")])
        if archivo:
            self.ruta_pcap_manual_var.set(archivo)

    def analizar_ruta_manual(self):

        ruta_pcap = self.ruta_pcap_manual_var.get().strip()
        if not ruta_pcap or not os.path.exists(ruta_pcap):
            messagebox.showerror("Ruta inválida", "Especifica una ruta válida a un archivo .pcap.")
            return

        # Crear ventana emergente
        popup = ctk.CTkToplevel(self)
        popup.title("Análisis de Archivo Manual")
        popup.geometry("700x500")
        
        label = ctk.CTkLabel(popup, text=f"Resultados del análisis para:\n{ruta_pcap}", font=("", 12, "bold"))
        label.pack(anchor="w", padx=10, pady=(10,0))
        
        txt = ctk.CTkTextbox(popup)
        txt.pack(fill="both", expand=True, padx=10, pady=10)
        txt.tag_config("warning", foreground="red")

        # Ejecutar análisis
        try:
            analizador = AnalizadorVulnerabilidades()
            analizador.analizar_archivo(ruta_pcap)
        except Exception as e:
            messagebox.showerror("Error de análisis", f"Ocurrió un error:\n{e}")
            popup.destroy()
            return

        # Mostrar alertas o éxito
        if analizador.alertas:
            txt.insert("end", "Advertencias detectadas:\n", "bold")
            for a in analizador.alertas:
                txt.insert("end", a + "\n", "warning")
        else:
            txt.insert("end", "No se detectaron amenazas.\n\n")

        # IPs más activas
        txt.insert("end", "\nIPs más activas:\n", "bold")
        for ip, cnt in sorted(analizador.conteo_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            txt.insert("end", f"{ip} → {cnt} paquetes\n")

        txt.see("end")

        # Botón cerrar
        ctk.CTkButton(popup, text="Cerrar", command=popup.destroy).pack(pady=5)


    def iniciar_captura(self):
        self.text_area.delete("1.0", "end")
        self.progress.set(0)
        self.label_estado.configure(text="")

        try:
            tiempo = int(self.tiempo_var.get())
            if tiempo <= 0:
                messagebox.showerror("Error", "El tiempo debe ser mayor a 0.")
                return
            iface_name = self.ifaces_dict[self.iface_var.get()]
            filtro = self.filtro_var.get().strip() or None
            ruta = self.ruta_guardado_var.get()
            self.sniffer = PacketSniffer(iface=iface_name, packet_callback=self.mostrar_paquete, bpf_filter=filtro, ruta_guardado=ruta)
            self.sniffer.start(tiempo)
        except ValueError:
            messagebox.showerror("Error", "Introduce un número válido para el tiempo.")
    def iniciar_captura_manual(self):
        self.text_area.delete("1.0", "end")
        self.progress.set(0)
        self.label_estado.configure(text="")

        try:
           iface_name = self.ifaces_dict[self.iface_var.get()]
           filtro = self.filtro_var.get().strip() or None
           ruta = self.ruta_guardado_var.get()
           self.sniffer = PacketSniffer(
              iface=iface_name,
              packet_callback=self.mostrar_paquete,
              bpf_filter=filtro,
              ruta_guardado=ruta
           )
           self.sniffer.start(tiempo_captura=999999)  # Simula sin límite
           self.label_estado.configure(text="Captura manual iniciada... (usa 'Detener' para finalizar)")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo iniciar la captura manual:\n{e}")
            
    def detener_captura(self):
        if self.sniffer:
           nombre = self.nombre_archivo_var.get().strip()
           self.sniffer.guardar_paquetes(nombre_archivo=nombre if nombre else None)
           self.sniffer.stop()
            
    def mostrar_paquete(self, resumen):
        if resumen.startswith(PROGRESO_PREFIX):
            valor = int(resumen.replace(PROGRESO_PREFIX, ""))
            self.progress.set(min(valor / 100, 1.0))
            self.label_estado.configure(text=f"Captura en progreso... {valor}%")
        else:
            self.text_area.insert("end", resumen + '\n')
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

    def toggle_paquetes(self):
        if self.mostrar_paquetes_var.get():
            # volver a mostrar el frame de resultados
            self.frame_resultados.pack(fill="both", expand=True, padx=10, pady=10)
        else:
            # ocultar el frame de resultados
            self.frame_resultados.pack_forget()

    def toggle_tema(self):
        nuevo_modo = "Dark" if self.tema_oscuro.get() else "Light"
        ctk.set_appearance_mode(nuevo_modo)

if __name__ == "__main__":
    app = SnifferGUI()
    app.mainloop()







