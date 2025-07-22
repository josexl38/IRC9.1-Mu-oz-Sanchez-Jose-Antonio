# IRC9.1-Mu-oz-Sanchez-Jose-Antonio

## CyberScope v2.0 - Herramienta de Análisis Forense Digital y Pentesting

### 🌐 Interfaz Web con Docker

CyberScope ahora incluye una interfaz web moderna desarrollada con Flask que permite:

- **Análisis Web Masivo**: Pega múltiples URLs y analízalas automáticamente
- **Análisis Forense de Archivos**: Sube archivos para análisis forense
- **Reportes Descargables**: Genera reportes en PDF y JSON
- **Interfaz Intuitiva**: Moderna y fácil de usar con progreso en tiempo real
- **Herramientas de Pentesting**: Escaneo de puertos, detección de vulnerabilidades, análisis SSL

#### 🚀 Ejecutar con Docker

```bash
# Construir y ejecutar con Docker Compose
docker-compose up --build

# Acceder a la interfaz web
# http://localhost:5000
```

#### 📋 Características de la Interfaz Web

**Análisis Web:**
- ✅ Análisis web básico (headers, contenido, IoCs)
- ✅ Detección de vulnerabilidades (SQL Injection, XSS, etc.)
- ✅ Análisis de certificados SSL
- ✅ Fuzzing de parámetros web
- ✅ Información WHOIS
- ✅ Escaneo de puertos
- ✅ Progreso en tiempo real con cancelación de análisis

**Análisis Forense:**
- ✅ Hash de archivos (MD5, SHA1, SHA256)
- ✅ Extracción de metadatos EXIF
- ✅ Metadatos de archivos PDF
- ✅ Extracción de IoCs de archivos de texto

**Reportes:**
- ✅ Generación automática de reportes PDF y JSON
- ✅ Descarga directa desde la interfaz web
- ✅ Historial de reportes generados

### Instalación

1. Clona el repositorio:
```bash
git clone <url-del-repositorio>
cd IRC9.1-Mu-oz-Sanchez-Jose-Antonio
```

2. Para uso local, crea un entorno virtual (recomendado):
```bash
python3 -m venv cyberscope-env
source cyberscope-env/bin/activate  # En Linux/Mac
# o
cyberscope-env\Scripts\activate     # En Windows
```

3. Instala las dependencias:
```bash
pip install -r requirements.txt
```

### Uso

#### Línea de comandos:
```bash
cd cyberscope
python main.py --help
```

#### Interfaz Web:
```bash
docker-compose up --build
# Abrir http://localhost:5000 en el navegador
```

### Ejemplos de uso:

```bash
# Hashear un archivo
python cyberscope/main.py --hash archivo.txt

# Buscar archivos sospechosos
python cyberscope/main.py --buscar /ruta/directorio --pdf

# Extraer metadatos EXIF
python cyberscope/main.py --exif imagen.jpg --json

# Análisis web
python cyberscope/main.py --webscan https://ejemplo.com --pdf

# Pentesting
python cyberscope/main.py --portscan 192.168.1.1 --pdf
python cyberscope/main.py --vulnscan https://ejemplo.com --json
python cyberscope/main.py --sslcheck ejemplo.com
python cyberscope/main.py --paramfuzz https://ejemplo.com/search
python cyberscope/main.py --pentest https://ejemplo.com --pdf --json

# Extraer IoCs de un archivo
python cyberscope/main.py --ioc log.txt --json --pdf
```

### Características:

- ✅ Análisis forense de archivos (hashing MD5, SHA1, SHA256)
- ✅ Extracción de metadatos EXIF de imágenes
- ✅ Análisis de metadatos PDF
- ✅ Búsqueda de archivos sospechosos
- ✅ Extracción de IoCs (IPs, URLs, emails, hashes)
- ✅ Análisis de seguridad web
- ✅ Consultas WHOIS e información de IPs
- ✅ Generación de reportes en PDF y JSON
- ✅ Escaneo de puertos TCP
- ✅ Detección de vulnerabilidades web básicas
- ✅ Análisis de certificados SSL
- ✅ Fuzzing de parámetros web
- ✅ Escaneo completo de pentesting

### Interfaz Web:

- ✅ Interfaz web moderna con Flask
- ✅ Análisis masivo de URLs
- ✅ Subida de archivos para análisis forense
- ✅ Reportes descargables (PDF/JSON)
- ✅ Progreso en tiempo real
- ✅ Cancelación de análisis
- ✅ Dockerizado para fácil despliegue

### Dependencias:

- `requests`: Para análisis web
- `beautifulsoup4`: Para parsing HTML
- `Pillow`: Para metadatos EXIF
- `PyPDF2`: Para metadatos PDF
- `reportlab`: Para generación de reportes PDF
- `ipwhois`: Para consultas de información IP
- `lxml`: Parser XML/HTML adicional
- `Flask`: Framework web para la interfaz
- `Werkzeug`: Utilidades web para Flask

### Arquitectura:
- **Versión modular**: Código organizado en módulos especializados
- **Interfaz web**: Flask con templates Bootstrap para una experiencia moderna
- **Dockerizado**: Fácil despliegue con Docker y docker-compose