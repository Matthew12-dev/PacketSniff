# PacketSniff : Detección de Amenazas con Heuristica y la implementación de ML
PacketSniff es una herramienta desarrollada en Python que permite la detección de amenazas en redes locales a través de la captura, análisis y clasificación inteligente del tráfico de red. Su principal objetivo es proporcionar una plataforma interactiva y automatizada para que analistas de seguridad o administradores de red puedan identificar patrones sospechosos, detectar posibles ataques y tomar decisiones con base en evidencia procesada. 

## Tabla de contenidos
## Descripción
Esta solución combina tres enfoques clave:
- Captura de tráfico en tiempo real, configurable mediante interfaz gráfica.
- Análisis heurístico de cabeceras y comportamientos anómalos.
- Clasificación automática de amenazas usando un modelo de Machine Learning (Random Forest) entrenado con datos del conjunto CICIDS 2017, reconocido en el campo de la ciberseguridad.

El proyecto integra distintos módulos esenciales:
- Una interfaz gráfica moderna (CustomTkinter) para usuarios no técnicos.
- Un simulador de ataques locales (SYN Flood, DNS Tunneling, UDP Flood, peticiones HTTP maliciosas) para validar la detección en entornos controlados.
- Un analizador de archivos .pcap, con heurísticas de seguridad y predicción automática.
- Un motor de análisis en segundo plano que agrupa los paquetes en bloques para procesarlos de forma eficiente.

## Instalación
- Descarga los archivos principales del proyecto:
newsniff.py, Analizador.py, modelo_randomforest.pkl.
También puedes incluir datosML.csv y entrenar_modelo.py si deseas modificar el modelo.

- Asegúrate de tener Python 3.8 o superior instalado.
Si no lo tienes, puedes descargarlo desde la página oficial de Python: www.python.org

- Instala las bibliotecas necesarias.
Abre una terminal o consola en la carpeta del proyecto e instala las dependencias que se encuentran en el archivo requirements.txt.
Este archivo contiene todas las librerías que usa el programa, como Scapy, PyShark, CustomTkinter y scikit-learn.

- Si usas Linux, instala Wireshark/TShark desde el gestor de paquetes de tu sistema.
Este paso es necesario para que el analizador pueda leer archivos de tráfico de red en formato .pcap.
En Windows, solo necesitas instalar Wireshark y asegurarte de marcar la opción "Add TShark to PATH" durante la instalación.

- Ejecuta el archivo newsniff.py para abrir la interfaz gráfica.
Desde ahí podrás seleccionar tu red, capturar paquetes, guardarlos, analizarlos y ver alertas si se detecta algún comportamiento sospechoso.

- (Opcional) Puedes usar simulador_ataque.py desde otra máquina para generar tráfico de prueba.
Este script lanza ataques como SYN Flood, UDP Flood, DNS Tunneling o tráfico HTTP modificado, para validar el sistema de detección.


## Autores
- Adauto Huaman, Matias Benjamin
- Berrocal Barrientos, Jorge Luis
- Racchumi Vasquez, Fernando Rafael
- Maita De La Cruz, Luois Edgar

## Documentación
