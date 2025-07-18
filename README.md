# IRC9.1-Mu-oz-Sanchez-Jose-Antonio

## CyberScope v2.0 - Herramienta de Análisis Forense Digital

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

### Dependencias:

- `requests`: Para análisis web
- `beautifulsoup4`: Para parsing HTML
- `Pillow`: Para metadatos EXIF
- `PyPDF2`: Para metadatos PDF
- `reportlab`: Para generación de reportes PDF
- `ipwhois`: Para consultas de información IP
- `lxml`: Parser XML/HTML adicional