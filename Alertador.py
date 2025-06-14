import joblib
import numpy as np

class AlertadorTiempoReal:
    def __init__(self, modelo_path='modelo_entrenado.pkl'):
        try:
            self.modelo = joblib.load(modelo_path)
        except Exception as e:
            print(f"[ERROR] No se pudo cargar el modelo: {e}")
            self.modelo = None

    def es_sospechoso(self, pkt):
        try:
            heuristica = False
            ml_sospechoso = False

            if 'IP' in pkt:
                ttl = int(pkt.ip.ttl) if hasattr(pkt.ip, 'ttl') else 64
                length = int(getattr(pkt, 'length', 0))
                dns_request = 1 if 'DNS' in pkt else 0
                num_dns = 0  # No puede calcularse en tiempo real por flujo

                # ML
                features = np.array([[ttl, length, num_dns, dns_request]])
                if self.modelo:
                    pred = self.modelo.predict(features)
                    ml_sospechoso = pred[0] == 1

            # Heurísticas
            if 'HTTP' in pkt:
                heuristica = True

            if 'TCP' in pkt:
                flags = getattr(pkt.tcp, 'flags', None)
                if flags:
                    flags = int(flags, 16)
                    if flags in [0, 1, 41]:  # NULL, FIN, XMAS
                        heuristica = True

            if 'ARP' in pkt:
                heuristica = True

            return ml_sospechoso or heuristica

        except:
            return False
