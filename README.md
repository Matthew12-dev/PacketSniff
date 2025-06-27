# PacketSniff : Detección de Amenazas con Heuristica y la implementación de ML
PacketSniff es una herramienta desarrollada en Python que permite la detección de amenazas en redes locales a través de la captura, análisis y clasificación inteligente del tráfico de red. Su principal objetivo es proporcionar una plataforma interactiva y automatizada para que analistas de seguridad o administradores de red puedan identificar patrones sospechosos, detectar posibles ataques y tomar decisiones con base en evidencia procesada.

Esta solución combina tres enfoques clave:

Captura de tráfico en tiempo real, configurable mediante interfaz gráfica.

Análisis heurístico de cabeceras y comportamientos anómalos.

Clasificación automática de amenazas usando un modelo de Machine Learning (Random Forest) entrenado con datos del conjunto CICIDS 2017, reconocido en el campo de la ciberseguridad.

El proyecto integra distintos módulos esenciales:

Una interfaz gráfica moderna (CustomTkinter) para usuarios no técnicos.

Un simulador de ataques locales (SYN Flood, DNS Tunneling, UDP Flood, peticiones HTTP maliciosas) para validar la detección en entornos controlados.

Un analizador de archivos .pcap, con heurísticas de seguridad y predicción automática.

Un motor de análisis en segundo plano que agrupa los paquetes en bloques para procesarlos de forma eficiente.

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
