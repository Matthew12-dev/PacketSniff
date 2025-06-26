# PacketSniff : Detección de Amenazas con Heuristica y la implementación de ML
Un Sniffer de paquetes hecho con Python, usando la libería socket y scapy , consiste en un lector de captura de tráfico de red que son procesados por una base de datos, donde se puede realizar un análisis sobre la composición de los paquetes, encabezados, protocolos, cifrado, etc. Para un análisis más inteligente, se implementará la Inteligencia Artificial con la librería OpenAI, su objetivo principal es proporcionar una solución completa para administradores de red o equipos de ciberseguridad, permitiéndoles identificar riesgos y tomar acciones correctivas con base en datos procesados y recomendaciones IA.

## Tabla de contenidos
## Descripción
Este proyecto realiza las siguientes acciones:

- Utilizar sniffer de tráfico en tiempo real (utilizando la libreria socket).
- Procesa los paquetes utilizando la clase Parser para obtener las cabeceras (IPv4, ICMP, TCP/UDP), protocolos(HTTP/HTTPs) y sus cifrados.
- Analiza las Cabeceras, Protocolos(TCP y UDP) y cifrado utilizando un modelo de aprendizaje automático (Isolation Forest).
- Genera un archivo TXT con los datos recopilados.
- Utiliza OpenAI GPT-3 para explicar las vulnerabilidades detectadas y encontrar soluciones.
## Instalación


## Autores
- Adauto Huaman, Matias Benjamin
- Berrocal Barrientos, Jorge Luis
- Racchumi Vasquez, Fernando Rafael
- Maita De La Cruz, Luois Edgar

## Documentación
