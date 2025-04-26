# PacketSniff
Un Sniffer de paquetes hecho con Python, usando la libería socket y scapy , consiste en un lector de captura de tráfico de red que son procesados por una base de datos, donde se puede realizar un análisis sobre la composición de los paquetes, encabezados, protocolos, cifrado, etc. Para un análisis más inteligente, se implementará la Inteligencia Artificial con la librería OpenAI, su objetivo principal es proporcionar una solución completa para administradores de red o equipos de ciberseguridad, permitiéndoles identificar riesgos y tomar acciones correctivas con base en datos procesados y recomendaciones IA.

Tabla de contenidos
## Descripción
Este proyecto realiza las siguientes acciones:

Capturar todo el tráfico en un cierto tiempo.
Analiza las latencias utilizando un modelo de aprendizaje automático (Isolation Forest) y un umbral de 0,2 segundos para detectar anomalías.
Calcula el ancho de banda a partir de las latencias.
Genera gráficos de latencias y ancho de banda.
Genera un archivo CSV con los datos recopilados.
Utiliza OpenAI GPT-3 para explicar las anomalías detectadas.
Instalación
Descargar el archivo .ZIP
Descomprimir el archivo y abrirlo en el IDE de su preferencia
Instalar las dependencias en la terminal con el comando: pip install -r requisitos.txt
Al ejecutar el programa se generará un enlace por el cual usted podrá iniciar las mediciones de latencia y ancho de banda de su red.

## Autores
- Adauto Huaman, Matias Benjamin
- Berrocal Barrientos, Jorge Luis
- Racchumi Vasquez, Fernando Rafael
- Maita De La Cruz, Luois Edgar

Documentación
