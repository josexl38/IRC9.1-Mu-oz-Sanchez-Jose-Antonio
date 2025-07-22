#!/usr/bin/env python3

import os
import json
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import threading
import time

# Importar módulos de CyberScope
from cyberscope.core.forensics import (
    hash_file, extraer_exif, extraer_pdf_meta, extraer_iocs
)
from cyberscope.core.webscan import (
    analizar_pagina_web, dirscan, login_check
)
from cyberscope.core.osint import whois_lookup, ip_lookup
from cyberscope.core.pentesting import (
    escanear_puertos, detectar_vulnerabilidades_web,
    analizar_certificado_ssl, fuzzing_parametros_web,
    escaneo_completo_pentesting
)
from cyberscope.core.report import exportar_json, generar_reporte_pdf
from cyberscope.core.utils import FINDINGS, logger

app = Flask(__name__)
app.secret_key = 'cyberscope-secret-key-2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REPORTS_FOLDER'] = 'reports'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Crear directorios necesarios
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

# Almacenamiento en memoria para análisis en progreso
analysis_status = {}

def clear_findings():
    """Limpiar hallazgos anteriores"""
    global FINDINGS
    FINDINGS.clear()

def generate_report_id():
    """Generar ID único para el reporte"""
    return str(uuid.uuid4())[:8]

def analyze_urls_background(urls, report_id, analysis_types):
    """Ejecutar análisis en background"""
    try:
        analysis_status[report_id]['status'] = 'running'
        analysis_status[report_id]['progress'] = 0
        
        clear_findings()
        
        total_urls = len(urls)
        
        for i, url in enumerate(urls):
            if analysis_status[report_id]['status'] == 'cancelled':
                break
                
            url = url.strip()
            if not url:
                continue
                
            analysis_status[report_id]['current_url'] = url
            analysis_status[report_id]['progress'] = int((i / total_urls) * 100)
            
            # Análisis web básico
            if 'webscan' in analysis_types:
                analizar_pagina_web(url)
            
            # Detección de vulnerabilidades
            if 'vulnscan' in analysis_types:
                detectar_vulnerabilidades_web(url)
            
            # Análisis SSL
            if 'sslcheck' in analysis_types:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    if parsed.scheme == 'https':
                        analizar_certificado_ssl(parsed.hostname)
                except:
                    pass
            
            # Fuzzing de parámetros
            if 'paramfuzz' in analysis_types:
                fuzzing_parametros_web(url)
            
            # WHOIS lookup
            if 'whois' in analysis_types:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    if parsed.hostname:
                        whois_lookup(parsed.hostname)
                except:
                    pass
            
            # Escaneo de puertos
            if 'portscan' in analysis_types:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    if parsed.hostname:
                        escanear_puertos(parsed.hostname)
                except:
                    pass
            
            time.sleep(1)  # Pausa entre URLs
        
        # Generar reportes
        analysis_status[report_id]['progress'] = 90
        analysis_status[report_id]['current_url'] = 'Generando reportes...'
        
        # Exportar JSON
        json_filename = f"reporte_{report_id}.json"
        json_path = os.path.join(app.config['REPORTS_FOLDER'], json_filename)
        exportar_json(json_path)
        
        # Generar PDF
        pdf_filename = f"reporte_{report_id}.pdf"
        pdf_path = os.path.join(app.config['REPORTS_FOLDER'], pdf_filename)
        generar_reporte_pdf(pdf_path)
        
        analysis_status[report_id]['status'] = 'completed'
        analysis_status[report_id]['progress'] = 100
        analysis_status[report_id]['json_file'] = json_filename
        analysis_status[report_id]['pdf_file'] = pdf_filename
        analysis_status[report_id]['findings_count'] = len(FINDINGS)
        analysis_status[report_id]['findings'] = FINDINGS.copy()
        
    except Exception as e:
        analysis_status[report_id]['status'] = 'error'
        analysis_status[report_id]['error'] = str(e)
        logger.error(f"Error en análisis background: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        urls_text = data.get('urls', '').strip()
        analysis_types = data.get('analysis_types', [])
        
        if not urls_text:
            return jsonify({'error': 'No se proporcionaron URLs'}), 400
        
        if not analysis_types:
            return jsonify({'error': 'Selecciona al menos un tipo de análisis'}), 400
        
        # Procesar URLs
        urls = [url.strip() for url in urls_text.split('\n') if url.strip()]
        
        if not urls:
            return jsonify({'error': 'No se encontraron URLs válidas'}), 400
        
        # Generar ID del reporte
        report_id = generate_report_id()
        
        # Inicializar estado del análisis
        analysis_status[report_id] = {
            'status': 'starting',
            'progress': 0,
            'current_url': '',
            'urls_count': len(urls),
            'analysis_types': analysis_types,
            'started_at': datetime.now().isoformat()
        }
        
        # Iniciar análisis en background
        thread = threading.Thread(
            target=analyze_urls_background,
            args=(urls, report_id, analysis_types)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'report_id': report_id,
            'message': 'Análisis iniciado correctamente'
        })
        
    except Exception as e:
        logger.error(f"Error iniciando análisis: {e}")
        return jsonify({'error': f'Error iniciando análisis: {str(e)}'}), 500

@app.route('/status/<report_id>')
def get_status(report_id):
    if report_id not in analysis_status:
        return jsonify({'error': 'Reporte no encontrado'}), 404
    
    return jsonify(analysis_status[report_id])

@app.route('/cancel/<report_id>', methods=['POST'])
def cancel_analysis(report_id):
    if report_id not in analysis_status:
        return jsonify({'error': 'Reporte no encontrado'}), 404
    
    analysis_status[report_id]['status'] = 'cancelled'
    return jsonify({'message': 'Análisis cancelado'})

@app.route('/download/<report_id>/<file_type>')
def download_report(report_id, file_type):
    if report_id not in analysis_status:
        return jsonify({'error': 'Reporte no encontrado'}), 404
    
    status = analysis_status[report_id]
    
    if status['status'] != 'completed':
        return jsonify({'error': 'El análisis no ha terminado'}), 400
    
    if file_type == 'json':
        filename = status.get('json_file')
    elif file_type == 'pdf':
        filename = status.get('pdf_file')
    else:
        return jsonify({'error': 'Tipo de archivo no válido'}), 400
    
    if not filename:
        return jsonify({'error': 'Archivo no disponible'}), 404
    
    file_path = os.path.join(app.config['REPORTS_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'Archivo no encontrado'}), 404
    
    return send_file(file_path, as_attachment=True)

@app.route('/forensics')
def forensics():
    return render_template('forensics.html')

@app.route('/upload_file', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No se seleccionó archivo'}), 400
        
        file = request.files['file']
        analysis_type = request.form.get('analysis_type')
        
        if file.filename == '':
            return jsonify({'error': 'No se seleccionó archivo'}), 400
        
        if not analysis_type:
            return jsonify({'error': 'Selecciona un tipo de análisis'}), 400
        
        # Guardar archivo
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        clear_findings()
        
        # Realizar análisis según el tipo
        if analysis_type == 'hash':
            hash_file(file_path)
        elif analysis_type == 'exif':
            extraer_exif(file_path)
        elif analysis_type == 'pdf':
            extraer_pdf_meta(file_path)
        elif analysis_type == 'ioc':
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                extraer_iocs(content)
        
        # Generar reporte
        report_id = generate_report_id()
        
        # Exportar resultados
        json_filename = f"forensics_{report_id}.json"
        json_path = os.path.join(app.config['REPORTS_FOLDER'], json_filename)
        exportar_json(json_path)
        
        pdf_filename = f"forensics_{report_id}.pdf"
        pdf_path = os.path.join(app.config['REPORTS_FOLDER'], pdf_filename)
        generar_reporte_pdf(pdf_path)
        
        # Limpiar archivo subido
        os.remove(file_path)
        
        return jsonify({
            'report_id': report_id,
            'findings_count': len(FINDINGS),
            'findings': FINDINGS,
            'json_file': json_filename,
            'pdf_file': pdf_filename
        })
        
    except Exception as e:
        logger.error(f"Error en análisis forense: {e}")
        return jsonify({'error': f'Error en análisis: {str(e)}'}), 500

@app.route('/reports')
def reports():
    """Página para ver reportes generados"""
    reports = []
    
    for report_id, status in analysis_status.items():
        if status['status'] == 'completed':
            reports.append({
                'id': report_id,
                'started_at': status.get('started_at'),
                'urls_count': status.get('urls_count', 0),
                'findings_count': status.get('findings_count', 0),
                'analysis_types': status.get('analysis_types', [])
            })
    
    return render_template('reports.html', reports=reports)

@app.route('/health')
def health():
    """Endpoint de salud para Docker"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)