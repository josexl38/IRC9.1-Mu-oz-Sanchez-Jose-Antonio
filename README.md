# IRC9.1-Mu-oz-Sanchez-Jose-Antonio

## CyberScope v2.0 - Herramienta de Análisis Forense Digital

### 🌐 Interfaz Web con Docker

CyberScope ahora incluye una interfaz web moderna desarrollada con Flask que permite:

- **Análisis Web Masivo**: Pega múltiples URLs y analízalas automáticamente
- **Análisis Forense de Archivos**: Sube archivos para análisis forense
- **Reportes Descargables**: Genera reportes en PDF y JSON
- **Interfaz Intuitiva**: Fácil de usar con progreso en tiempo real

#### 🚀 Ejecutar con Docker

```bash
# Construir y ejecutar con Docker Compose
docker-compose up --build

# O ejecutar manualmente
docker build -t cyberscope-web .
docker run -p 5000:5000 -v $(pwd)/reports:/app/reports cyberscope-web
```

Luego abre tu navegador en: http://localhost:5000

#### 📋 Características de la Interfaz Web

**Análisis Web:**
- ✅ Análisis web básico (headers, contenido, IoCs)
- ✅ Detección de vulnerabilidades (SQL Injection, XSS, etc.)
- ✅ Análisis de certificados SSL
- ✅ Fuzzing de parámetros web
- ✅ Información WHOIS
- ✅ Escaneo de puertos

**Análisis Forense:**
- ✅ Hash de archivos (MD5, SHA1, SHA256)
- ✅ Extracción de metadatos EXIF
- ✅ Metadatos de archivos PDF
- ✅ Extracción de IoCs de archivos de texto

### Instalación

1. Clona el repositorio:
```bash
git clone <url-del-repositorio>
cd IRC9.1-Mu-oz-Sanchez-Jose-Antonio
```

2. Crea un entorno virtual (recomendado):
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

#### Versión monolítica:
```bash
python cyberscope.py --help
```

#### Versión modular:
```bash
cd cyberscope
python main.py --help
```

### Ejemplos de uso:

```bash
# Hashear un archivo
python cyberscope.py --hash archivo.txt

# Buscar archivos sospechosos
python cyberscope.py --buscar /ruta/directorio --pdf

# Extraer metadatos EXIF
python cyberscope.py --exif imagen.jpg --json

# Análisis web
python cyberscope.py --webscan https://ejemplo.com --pdf

# Pentesting
python cyberscope.py --portscan 192.168.1.1 --pdf
python cyberscope.py --vulnscan https://ejemplo.com --json
python cyberscope.py --sslcheck ejemplo.com
python cyberscope.py --paramfuzz https://ejemplo.com/search

# Extraer IoCs de un archivo
python cyberscope.py --ioc log.txt --json --pdf
```

### Características:

- ✅ Análisis forense de archivos (hashing MD5, SHA1, SHA256)
- ✅ Extracción de metadatos EXIF de imágenes
- ✅ Análisis de metadatos PDF
- ✅ Búsqueda de archivos sospechosos
- ✅ Extracción de IoCs (IPs, URLs, emails, hashes)
- ✅ Análisis de seguridad web
- ✅ Fuzzing de directorios
- ✅ Consultas WHOIS e información de IPs
- ✅ Generación de reportes en PDF y JSON
- ✅ Escaneo de puertos TCP
- ✅ Detección de vulnerabilidades web básicas
- ✅ Análisis de certificados SSL
- ✅ Fuzzing de parámetros web

### Interfaz Web:

- ✅ Interfaz web moderna con Flask
- ✅ Análisis masivo de URLs
- ✅ Subida de archivos para análisis forense
- ✅ Reportes descargables (PDF/JSON)
- ✅ Progreso en tiempo real
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