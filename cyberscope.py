#!/usr/bin/env python3

import os
import argparse
import hashlib
import re
import time
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

# Importaciones con manejo de errores
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("[WARNING] PIL no está disponible. Funciones de EXIF deshabilitadas.")

try:
    from PyPDF2 import PdfReader
    PYPDF2_AVAILABLE = True
except ImportError:
    PYPDF2_AVAILABLE = False
    print("[WARNING] PyPDF2 no está disponible. Funciones de PDF deshabilitadas.")

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("[WARNING] ReportLab no está disponible. Generación de PDF deshabilitada.")

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cyberscope.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Lista global de hallazgos
FINDINGS = []

# === FUNCIONES FORENSES MEJORADAS ===

def hash_file(filepath: str, algos: List[str] = ["md5", "sha1", "sha256"]) -> Optional[Dict[str, str]]:
    """
    Calcula hashes de un archivo con múltiples algoritmos para garantizar integridad.
    
    Args:
        filepath: Ruta del archivo a hashear
        algos: Lista de algoritmos de hash a usar
        
    Returns:
        Diccionario con los hashes calculados o None si hay error
    """
    try:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"El archivo {filepath} no existe")
            
        if not os.path.isfile(filepath):
            raise ValueError(f"{filepath} no es un archivo válido")
            
        hashes = {}
        file_size = os.path.getsize(filepath)
        
        for algo in algos:
            try:
                h = hashlib.new(algo)
                with open(filepath, 'rb') as f:
                    while chunk := f.read(8192):
                        h.update(chunk)
                hashes[algo] = h.hexdigest()
                FINDINGS.append(f"[HASH] {algo.upper()} - {filepath}: {hashes[algo]}")
            except ValueError as e:
                logger.error(f"Algoritmo de hash inválido '{algo}': {e}")
                continue
                
        FINDINGS.append(f"[FILE_SIZE] {filepath}: {file_size} bytes")
        logger.info(f"Archivo hasheado exitosamente: {filepath}")
        return hashes
        
    except Exception as e:
        error_msg = f"No se pudo hashear {filepath}: {e}"
        FINDINGS.append(f"[ERROR] {error_msg}")
        logger.error(error_msg)
        return None

def hash_directory(dirpath: str, algos: List[str] = ["md5", "sha1", "sha256"]) -> Optional[Dict[str, Dict[str, str]]]:
    """
    Hashea todos los archivos en un directorio recursivamente.
    
    Args:
        dirpath: Ruta del directorio a procesar
        algos: Lista de algoritmos de hash a usar
        
    Returns:
        Diccionario con los hashes de todos los archivos
    """
    try:
        if not os.path.exists(dirpath):
            raise FileNotFoundError(f"El directorio {dirpath} no existe")
            
        if not os.path.isdir(dirpath):
            raise ValueError(f"{dirpath} no es un directorio válido")
            
        hashes = {}
        file_count = 0
        
        for root, _, files in os.walk(dirpath):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    hashes[full_path] = hash_file(full_path, algos)
                    file_count += 1
                except Exception as e:
                    logger.warning(f"Error procesando {full_path}: {e}")
                    continue
                    
        FINDINGS.append(f"[DIRECTORY_SCAN] Procesados {file_count} archivos en {dirpath}")
        logger.info(f"Directorio procesado: {dirpath} ({file_count} archivos)")
        return hashes
        
    except Exception as e:
        error_msg = f"No se pudo procesar directorio {dirpath}: {e}"
        FINDINGS.append(f"[ERROR] {error_msg}")
        logger.error(error_msg)
        return None

def get_file_timestamps(filepath: str) -> Optional[Dict[str, str]]:
    """
    Extrae fechas de creación, modificación y acceso de un archivo (MAC times).
    
    Args:
        filepath: Ruta del archivo
        
    Returns:
        Diccionario con los timestamps o None si hay error
    """
    try:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"El archivo {filepath} no existe")
            
        stats = os.stat(filepath)
        times = {
            "creacion": datetime.fromtimestamp(stats.st_ctime).isoformat(),
            "modificacion": datetime.fromtimestamp(stats.st_mtime).isoformat(),
            "acceso": datetime.fromtimestamp(stats.st_atime).isoformat()
        }
        
        for k, v in times.items():
            FINDINGS.append(f"[TIMESTAMP] {k} - {filepath}: {v}")
            
        return times
        
    except Exception as e:
        error_msg = f"No se pudo extraer timestamps de {filepath}: {e}"
        FINDINGS.append(f"[ERROR] {error_msg}")
        logger.error(error_msg)
        return None

def buscar_sospechosos(path: str, extensiones: List[str] = [".exe", ".bat", ".dll", ".scr", ".ps1", ".vbs", ".cmd", ".com"]) -> List[str]:
    """
    Busca archivos sospechosos por extensión en un directorio.
    
    Args:
        path: Ruta del directorio a buscar
        extensiones: Lista de extensiones sospechosas
        
    Returns:
        Lista de archivos encontrados
    """
    try:
        if not os.path.exists(path):
            raise FileNotFoundError(f"El directorio {path} no existe")
            
        encontrados = []
        
        for root, _, files in os.walk(path):
            for f in files:
                if any(f.lower().endswith(ext.lower()) for ext in extensiones):
                    full_path = os.path.join(root, f)
                    encontrados.append(full_path)
                    FINDINGS.append(f"[SOSPECHOSO] {full_path}")
                    get_file_timestamps(full_path)
                    
        FINDINGS.append(f"[SCAN_RESULT] Encontrados {len(encontrados)} archivos sospechosos en {path}")
        logger.info(f"Búsqueda completada: {len(encontrados)} archivos sospechosos encontrados")
        return encontrados
        
    except Exception as e:
        error_msg = f"No se pudo buscar en {path}: {e}"
        FINDINGS.append(f"[ERROR] {error_msg}")
        logger.error(error_msg)
        return []

def extraer_exif(img_path: str) -> Optional[Dict]:
    """
    Extrae metadatos EXIF de una imagen.
    
    Args:
        img_path: Ruta de la imagen
        
    Returns:
        Diccionario con metadatos EXIF o None si hay error
    """
    if not PIL_AVAILABLE:
        FINDINGS.append(f"[ERROR] PIL no disponible para extraer EXIF de {img_path}")
        return None
        
    try:
        if not os.path.exists(img_path):
            raise FileNotFoundError(f"La imagen {img_path} no existe")
            
        with Image.open(img_path) as img:
            exif_data = img._getexif()
            
            if not exif_data:
                FINDINGS.append(f"[EXIF] {img_path}: Sin metadatos EXIF")
                return None
                
            exif_dict = {}
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                exif_dict[tag] = value
                FINDINGS.append(f"[EXIF] {img_path} - {tag}: {value}")
                
            return exif_dict
            
    except Exception as e:
        error_msg = f"No se pudo extraer EXIF de {img_path}: {e}"
        FINDINGS.append(f"[ERROR] {error_msg}")
        logger.error(error_msg)
        return None

def extraer_pdf_meta(pdf_path: str) -> Optional[Dict]:
    """
    Extrae metadatos de un archivo PDF.
    
    Args:
        pdf_path: Ruta del archivo PDF
        
    Returns:
        Diccionario con metadatos o None si hay error
    """
    if not PYPDF2_AVAILABLE:
        FINDINGS.append(f"[ERROR] PyPDF2 no disponible para extraer metadatos de {pdf_path}")
        return None
        
    try:
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"El archivo PDF {pdf_path} no existe")
            
        with open(pdf_path, 'rb') as f:
            reader = PdfReader(f)
            meta = reader.metadata
            
            if not meta:
                FINDINGS.append(f"[PDF_META] {pdf_path}: Sin metadatos")
                return None
                
            meta_dict = {}
            for k, v in meta.items():
                meta_dict[k] = str(v)
                FINDINGS.append(f"[PDF_META] {pdf_path} - {k}: {v}")
                
            # Información adicional
            FINDINGS.append(f"[PDF_INFO] {pdf_path} - Páginas: {len(reader.pages)}")
            FINDINGS.append(f"[PDF_INFO] {pdf_path} - Encriptado: {reader.is_encrypted}")
            
            return meta_dict
            
    except Exception as e:
        error_msg = f"No se pudo extraer metadatos de {pdf_path}: {e}"
        FINDINGS.append(f"[ERROR] {error_msg}")
        logger.error(error_msg)
        return None

def extraer_iocs(texto: str) -> Optional[Dict[str, List[str]]]:
    """
    Extrae indicadores de compromiso (IoCs) de un texto.
    
    Args:
        texto: Texto a analizar
        
    Returns:
        Diccionario con IoCs encontrados
    """
    try:
        # Patrones mejorados
        patterns = {
          "ips": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
          "urls": r'https?://[^\s<>"{}|\\^`\[\]]+',
          "emails": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
          "domains": r'\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b',
          "md5": r'\b[a-fA-F0-9]{32}\b',
          "sha1": r'\b[a-fA-F0-9]{40}\b',
          "sha256": r'\b[a-fA-F0-9]{64}\b'
        }
        
        results = {}
        
        for ioc_type, pattern in patterns.items():
            matches = list(set(re.findall(pattern, texto)))  # Usar set para eliminar duplicados
            results[ioc_type] = matches
            
            for match in matches:
                FINDINGS.append(f"[IOC] {ioc_type.upper()}: {match}")
                
        total_iocs = sum(len(matches) for matches in results.values())
        FINDINGS.append(f"[IOC_SUMMARY] Total de IoCs encontrados: {total_iocs}")
        
        return results
        
    except Exception as e:
        error_msg = f"No se pudo extraer IoCs: {e}"
        FINDINGS.append(f"[ERROR] {error_msg}")
        logger.error(error_msg)
        return None

import requests
from bs4 import BeautifulSoup

def analizar_pagina_web(url: str, timeout: int = 10) -> bool:
    """
    Realiza un análisis de cabeceras y contenido básico en una URL.
    """
    FINDINGS.append(f"[WEBSCAN] Iniciando escaneo de: {url}")
    try:
        response = requests.get(url, timeout=timeout)
    except requests.exceptions.RequestException as e:
        FINDINGS.append(f"[WEBSCAN_ERROR] No se pudo acceder a {url}: {e}")
        logger.error(f"Fallo al conectar con {url}: {e}")
        return False

    FINDINGS.append(f"[WEBSCAN] Código de estado: {response.status_code}")

    # === Cabeceras de seguridad esperadas ===
    headers_esperadas = [
        "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
        "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"
    ]

    for header in headers_esperadas:
        if header not in response.headers:
            FINDINGS.append(f"[WEBHEADER_MISSING] {header} no está presente")
        else:
            FINDINGS.append(f"[WEBHEADER] {header}: {response.headers[header]}")

    # === Extraer texto y buscar IoCs ===
    try:
        soup = BeautifulSoup(response.text, "html.parser")
        contenido = soup.get_text()
        FINDINGS.append(f"[WEBCONTENT] Longitud del contenido visible: {len(contenido)} caracteres")
        extraer_iocs(contenido)
    except Exception as e:
        FINDINGS.append(f"[WEBPARSE_ERROR] Error procesando contenido HTML: {e}")
        logger.warning(f"Error parsing HTML de {url}: {e}")

    # === Buscar posibles claves/API secrets en código fuente ===
    patrones_secrets = [
        r"(api_key|apikey|secret|token|authorization)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}",
        r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"  # JWT
    ]

    for pattern in patrones_secrets:
        matches = re.findall(pattern, response.text, re.IGNORECASE)
        for match in matches:
            FINDINGS.append(f"[WEB_SECRET] Posible clave o token encontrado: {match[:80]}...")

    FINDINGS.append(f"[WEBSCAN] Análisis completo de: {url}")
    return True

def dirscan(url: str, wordlist_path: str, codes=[200, 301, 302]) -> None:
    try:
        with open(wordlist_path) as f:
            paths = [line.strip() for line in f if line.strip()]
    except Exception as e:
        FINDINGS.append(f"[ERROR] No se pudo cargar wordlist: {e}")
        return

    FINDINGS.append(f"[DIRSCAN] Iniciando fuzzing en {url}")
    for path in paths:
        test_url = f"{url.rstrip('/')}/{path}"
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code in codes:
                FINDINGS.append(f"[DIR_FOUND] {test_url} - Código: {r.status_code}")
        except:
            continue
    FINDINGS.append("[DIRSCAN] Fuzzing completado")

def login_check(url: str) -> None:
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        found = False

        if soup.find('form'):
            for form in soup.find_all('form'):
                inputs = [i.get('type') for i in form.find_all('input')]
                if 'password' in inputs:
                    FINDINGS.append(f"[LOGIN_FORM] Posible formulario de login en {url}")
                    found = True

        for keyword in ['admin', 'login', 'auth']:
            if keyword in url.lower():
                FINDINGS.append(f"[LOGIN_URL_HINT] URL sospechosa de login: {url}")
                found = True

        if not found:
            FINDINGS.append(f"[LOGINCHECK] No se detectó formulario de login en {url}")
    except Exception as e:
        FINDINGS.append(f"[ERROR] LoginCheck falló: {e}")

def whois_lookup(domain: str):
    try:
        res = os.popen(f"whois {domain}").read()
        if res:
            FINDINGS.append(f"[WHOIS] Resultado WHOIS para {domain}:\n{res[:500]}")
        else:
            FINDINGS.append(f"[WHOIS] No se obtuvo información WHOIS para {domain}")
    except Exception as e:
        FINDINGS.append(f"[ERROR] WHOIS falló: {e}")

def ip_lookup(ip: str):
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        FINDINGS.append(f"[IPINFO] Información sobre {ip}:")
        FINDINGS.append(f"[IPINFO] ASN: {res.get('asn')}")
        FINDINGS.append(f"[IPINFO] Organización: {res.get('network', {}).get('name')}")
        FINDINGS.append(f"[IPINFO] País: {res.get('network', {}).get('country')}")
    except Exception as e:
        FINDINGS.append(f"[ERROR] IP Lookup falló: {e}")

# === HERRAMIENTAS DE PENTESTING ===

def escanear_puertos(host: str, puertos: list = None, timeout: int = 1) -> dict:
    """Escanea puertos TCP en un host específico."""
    if puertos is None:
        puertos = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
    
    FINDINGS.append(f"[PORTSCAN] Iniciando escaneo de puertos en {host}")
    
    resultados = {"host": host, "abiertos": [], "cerrados": []}
    
    for puerto in puertos:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            resultado = sock.connect_ex((host, puerto))
            
            if resultado == 0:
                resultados["abiertos"].append(puerto)
                FINDINGS.append(f"[PORT_OPEN] {host}:{puerto} - ABIERTO")
            else:
                resultados["cerrados"].append(puerto)
                
            sock.close()
        except Exception as e:
            logger.debug(f"Error escaneando puerto {puerto}: {e}")
    
    FINDINGS.append(f"[PORTSCAN_RESULT] {host} - Abiertos: {len(resultados['abiertos'])}")
    return resultados

def detectar_vulnerabilidades_web(url: str) -> dict:
    """Detecta vulnerabilidades web comunes."""
    FINDINGS.append(f"[VULNSCAN] Iniciando detección de vulnerabilidades en {url}")
    
    vulnerabilidades = {"sql_injection": [], "xss": [], "directory_traversal": []}
    
    try:
        # SQL Injection básico
        sql_payloads = ["'", "1' OR '1'='1", "'; DROP TABLE users; --"]
        for payload in sql_payloads:
            try:
                test_url = f"{url}?id={payload}"
                r = requests.get(test_url, timeout=5)
                sql_errors = ["mysql_fetch_array", "ORA-01756", "Microsoft OLE DB Provider"]
                
                for error in sql_errors:
                    if error.lower() in r.text.lower():
                        vulnerabilidades["sql_injection"].append({"payload": payload, "url": test_url})
                        FINDINGS.append(f"[VULN_SQL] Posible SQL Injection: {test_url}")
                        break
            except:
                continue
        
        # XSS básico
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        for payload in xss_payloads:
            try:
                test_url = f"{url}?search={payload}"
                r = requests.get(test_url, timeout=5)
                if payload in r.text:
                    vulnerabilidades["xss"].append({"payload": payload, "url": test_url})
                    FINDINGS.append(f"[VULN_XSS] Posible XSS: {test_url}")
            except:
                continue
                
    except Exception as e:
        FINDINGS.append(f"[VULNSCAN_ERROR] Error: {e}")
    
    total_vulns = sum(len(v) for v in vulnerabilidades.values())
    FINDINGS.append(f"[VULNSCAN_RESULT] {total_vulns} vulnerabilidades encontradas")
    return vulnerabilidades

def analizar_certificado_ssl(hostname: str, port: int = 443) -> dict:
    """Analiza el certificado SSL de un servidor."""
    FINDINGS.append(f"[SSL_ANALYSIS] Analizando certificado SSL de {hostname}:{port}")
    
    try:
        import ssl
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                cert_info = {
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "not_after": cert.get('notAfter')
                }
                
                FINDINGS.append(f"[SSL_CERT] Emisor: {cert_info['issuer'].get('organizationName', 'N/A')}")
                FINDINGS.append(f"[SSL_CERT] Válido hasta: {cert_info['not_after']}")
                
                return cert_info
                
    except Exception as e:
        FINDINGS.append(f"[SSL_ERROR] Error: {e}")
        return {"error": str(e)}

def fuzzing_parametros_web(url: str) -> dict:
    """Realiza fuzzing básico de parámetros web."""
    FINDINGS.append(f"[PARAM_FUZZ] Iniciando fuzzing de parámetros en {url}")
    
    parametros = ["id", "user", "page", "file", "search"]
    payloads = ["admin", "test", "1", "../etc/passwd", "' OR '1'='1"]
    
    resultados = {"interesting": []}
    
    try:
        base_response = requests.get(url, timeout=5)
        base_length = len(base_response.text)
        
        for param in parametros:
            for payload in payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = requests.get(test_url, timeout=3)
                    
                    if abs(len(response.text) - base_length) > 100:
                        resultados["interesting"].append(test_url)
                        FINDINGS.append(f"[PARAM_INTERESTING] {test_url}")
                        
                except:
                    continue
                    
    except Exception as e:
        FINDINGS.append(f"[PARAM_FUZZ_ERROR] Error: {e}")
    
    FINDINGS.append(f"[PARAM_FUZZ_RESULT] {len(resultados['interesting'])} respuestas interesantes")
    return resultados

def exportar_json(nombre: str = "hallazgos_forenses.json") -> bool:
    """
    Exporta los hallazgos a un archivo JSON.
    
    Args:
        nombre: Nombre del archivo JSON
        
    Returns:
        True si se exportó exitosamente, False en caso contrario
    """
    try:
        data = {
            "timestamp": datetime.now().isoformat(),
            "version": "CyberScope v2.0",
            "total_findings": len(FINDINGS),
            "findings": FINDINGS
        }
        
        with open(nombre, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
        logger.info(f"Hallazgos exportados a JSON: {nombre}")
        return True
        
    except Exception as e:
        logger.error(f"Error exportando a JSON: {e}")
        return False

# === REPORTE PDF MEJORADO ===

def generar_reporte_pdf(nombre: str = "reporte_forense.pdf") -> bool:
    """
    Genera un reporte PDF con los hallazgos forenses.
    
    Args:
        nombre: Nombre del archivo PDF
        
    Returns:
        True si se generó exitosamente, False en caso contrario
    """
    if not REPORTLAB_AVAILABLE:
        logger.error("ReportLab no está disponible para generar PDF")
        return False
        
    try:
        c = canvas.Canvas(nombre, pagesize=letter)
        width, height = letter
        
        # Encabezado
        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, height - 50, "CyberScope - Reporte Forense")
        
        c.setFont("Helvetica", 12)
        c.drawString(40, height - 80, f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(40, height - 100, "Generado por: CyberScope v2.0")
        c.drawString(40, height - 120, f"Total de hallazgos: {len(FINDINGS)}")
        
        # Línea separadora
        c.line(40, height - 140, width - 40, height - 140)
        
        y = height - 170
        current_section = None
        
        for finding in FINDINGS:
            # Verificar si necesitamos una nueva página
            if y < 50:
                c.showPage()
                y = height - 50
                
            # Extraer el tipo de hallazgo
            if "]" in finding:
                section = finding.split("]")[0][1:]
                if section != current_section:
                    y -= 10
                    c.setFont("Helvetica-Bold", 12)
                    c.setFillColor(colors.darkblue)
                    c.drawString(40, y, f"=== {section} ===")
                    y -= 20
                    current_section = section
                    c.setFillColor(colors.black)
                    
            c.setFont("Helvetica", 10)
            
            # Dividir líneas largas
            max_width = width - 100
            if len(finding) > 80:
                words = finding.split()
                line = ""
                for word in words:
                    test_line = f"{line} {word}" if line else word
                    if len(test_line) > 80:
                        c.drawString(50, y, line)
                        y -= 15
                        line = word
                    else:
                        line = test_line
                if line:
                    c.drawString(50, y, line)
                    y -= 15
            else:
                c.drawString(50, y, finding)
                y -= 15
                
        c.save()
        logger.info(f"Reporte PDF generado: {nombre}")
        return True
        
    except Exception as e:
        logger.error(f"No se pudo generar el reporte PDF: {e}")
        return False

# === CLI MEJORADO ===

def main():
    parser = argparse.ArgumentParser(
        description="CyberScope v2.0 - Herramienta de Análisis Forense Digital",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
    python cyberscope.py --hash archivo.txt
    python cyberscope.py --hash /ruta/directorio
    python cyberscope.py --buscar /ruta/directorio --pdf
    python cyberscope.py --exif imagen.jpg --json
    python cyberscope.py --ioc log.txt --pdf --json
        """
    )
    
    # Argumentos principales
    parser.add_argument("--hash", help="Archivo o directorio a hashear")
    parser.add_argument("--buscar", help="Buscar archivos sospechosos en directorio")
    parser.add_argument("--exif", help="Extraer metadatos EXIF de imagen")
    parser.add_argument("--pdfmeta", help="Extraer metadatos de archivo PDF")
    parser.add_argument("--ioc", help="Extraer IoCs de archivo de texto")
    parser.add_argument("--webscan", help="Escanea una página web y analiza cabeceras y contenido")
    parser.add_argument("--dirscan", nargs=2, metavar=('URL', 'WORDLIST'), help="Fuzzing de rutas en URL con wordlist")
    parser.add_argument("--logincheck", help="Buscar formulario de login en URL")
    parser.add_argument("--whois", help="Consulta WHOIS de un dominio")
    parser.add_argument("--ipinfo", help="Lookup de IP (ASN, país, etc)")

    # Argumentos de pentesting
    parser.add_argument("--portscan", help="Escanear puertos de un host")
    parser.add_argument("--vulnscan", help="Detectar vulnerabilidades web en URL")
    parser.add_argument("--sslcheck", help="Analizar certificado SSL de un host")
    parser.add_argument("--paramfuzz", help="Fuzzing de parámetros web en URL")

    # Argumentos de salida
    parser.add_argument("--pdf", action="store_true", help="Generar reporte PDF")
    parser.add_argument("--json", action="store_true", help="Exportar hallazgos a JSON")
    parser.add_argument("--output", help="Directorio de salida para reportes")
    
    # Argumentos de configuración
    parser.add_argument("--verbose", "-v", action="store_true", help="Salida detallada")
    parser.add_argument("--version", action="version", version="CyberScope v2.0")
    
    args = parser.parse_args()
    
    # Configurar logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Cambiar directorio de trabajo si se especifica
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        os.chdir(args.output)
    
    # Procesar argumentos
    if args.hash:
        if os.path.isdir(args.hash):
            logger.info(f"Procesando directorio: {args.hash}")
            hash_directory(args.hash)
        elif os.path.isfile(args.hash):
            logger.info(f"Procesando archivo: {args.hash}")
            hash_file(args.hash)
        else:
            logger.error(f"Ruta no válida: {args.hash}")
            
    if args.buscar:
        logger.info(f"Buscando archivos sospechosos en: {args.buscar}")
        buscar_sospechosos(args.buscar)
        
    if args.exif:
        logger.info(f"Extrayendo EXIF de: {args.exif}")
        extraer_exif(args.exif)
        
    if args.pdfmeta:
        logger.info(f"Extrayendo metadatos de PDF: {args.pdfmeta}")
        extraer_pdf_meta(args.pdfmeta)
        
    if args.ioc:
        logger.info(f"Extrayendo IoCs de: {args.ioc}")
        try:
            with open(args.ioc, 'r', encoding='utf-8') as f:
                extraer_iocs(f.read())
        except Exception as e:
            error_msg = f"No se pudo leer archivo de IoCs {args.ioc}: {e}"
            FINDINGS.append(f"[ERROR] {error_msg}")
            logger.error(error_msg)

    if args.webscan:
        logger.info(f"Analizando página web: {args.webscan}")
        analizar_pagina_web(args.webscan)

    if args.dirscan:
        url, wl = args.dirscan
        logger.info(f"Fuzzing de directorios en: {url} con {wl}")
        dirscan(url, wl)

    if args.logincheck:
        logger.info(f"Chequeando login en: {args.logincheck}")
        login_check(args.logincheck)

    if args.whois:
        logger.info(f"Ejecutando WHOIS en: {args.whois}")
        whois_lookup(args.whois)

    if args.ipinfo:
        logger.info(f"Consultando IP info de: {args.ipinfo}")
        ip_lookup(args.ipinfo)

    # Pentesting
    if args.portscan:
        logger.info(f"Escaneando puertos de: {args.portscan}")
        escanear_puertos(args.portscan)

    if args.vulnscan:
        logger.info(f"Detectando vulnerabilidades en: {args.vulnscan}")
        detectar_vulnerabilidades_web(args.vulnscan)

    if args.sslcheck:
        logger.info(f"Analizando certificado SSL de: {args.sslcheck}")
        analizar_certificado_ssl(args.sslcheck)

    if args.paramfuzz:
        logger.info(f"Fuzzing de parámetros en: {args.paramfuzz}")
        fuzzing_parametros_web(args.paramfuzz)

    
    # Generar reportes
    if args.json:
        exportar_json()
        
    if args.pdf:
        generar_reporte_pdf()
    
    # Mostrar resumen
    if FINDINGS:
        print(f"\n[+] Análisis completado: {len(FINDINGS)} hallazgos registrados")
        print(f"[+] Log guardado en: cyberscope.log")
        if args.json:
            print(f"[+] Hallazgos exportados a: hallazgos_forenses.json")
        if args.pdf:
            print(f"[+] Reporte PDF generado: reporte_forense.pdf")
    else:
        print("[-] No se encontraron hallazgos")

if __name__ == "__main__":
    main()
