import json
import os
from datetime import datetime
from pathlib import Path
import re

# Librerías para PDF
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from .utils import logger
import textwrap

class CyberScopePDFGenerator:
    def __init__(self):
        """Inicializa el generador de PDF para CyberScope"""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab no está disponible. Instala con: pip install reportlab")
        
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        
    def setup_custom_styles(self):
        """Define estilos personalizados para el PDF"""
        # Estilo para el título principal
        self.styles.add(ParagraphStyle(
            name='CyberScopeTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1a365d'),
            fontName='Helvetica-Bold'
        ))
        
        # Estilo para subtítulos de sección
        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#2d3748'),
            fontName='Helvetica-Bold'
        ))
        
        # Estilo para hallazgos críticos
        self.styles.add(ParagraphStyle(
            name='CriticalFinding',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=8,
            spaceBefore=5,
            textColor=colors.HexColor('#c53030'),
            fontName='Helvetica-Bold',
            leftIndent=15
        ))
        
        # Estilo para hallazgos normales
        self.styles.add(ParagraphStyle(
            name='NormalFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=5,
            leftIndent=15,
            fontName='Helvetica'
        ))
        
        # Estilo para análisis ChatGPT
        self.styles.add(ParagraphStyle(
            name='ChatGPTAnalysis',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=10,
            spaceBefore=10,
            alignment=TA_JUSTIFY,
            leftIndent=10,
            rightIndent=10,
            fontName='Helvetica',
            backColor=colors.HexColor('#f7fafc'),
            wordWrap='LTR'
        ))
        
        # Estilo para recomendaciones
        self.styles.add(ParagraphStyle(
            name='Recommendation',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=5,
            leftIndent=20,
            bulletIndent=15,
            fontName='Helvetica'
        ))
        
        # Estilo para metadatos
        self.styles.add(ParagraphStyle(
            name='Metadata',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#718096'),
            alignment=TA_CENTER,
            fontName='Helvetica-Oblique'
        ))

    def create_header_footer(self, canvas_obj, doc):
        """Crea encabezado y pie de página personalizados"""
        canvas_obj.saveState()
        
        # Encabezado
        canvas_obj.setFont('Helvetica-Bold', 12)
        canvas_obj.setFillColor(colors.HexColor('#1a365d'))
        canvas_obj.drawString(50, A4[1] - 30, "CyberScope v2.0 - Reporte de Análisis Forense")
        
        # Línea decorativa
        canvas_obj.setStrokeColor(colors.HexColor('#1a365d'))
        canvas_obj.setLineWidth(2)
        canvas_obj.line(50, A4[1] - 40, A4[0] - 50, A4[1] - 40)
        
        # Pie de página
        canvas_obj.setFont('Helvetica', 9)
        canvas_obj.setFillColor(colors.HexColor('#718096'))
        canvas_obj.drawString(50, 30, f"Generado: {datetime.now().strftime('%d/%m/%Y %H:%M')}")
        canvas_obj.drawRightString(A4[0] - 50, 30, f"Página {doc.page}")
        
        canvas_obj.restoreState()

    def generate_comprehensive_report(self, analysis_data, output_filename=None):
        """
        Genera un reporte PDF completo con análisis técnico y ChatGPT
        
        Args:
            analysis_data (dict): Datos del análisis completo
            output_filename (str): Nombre del archivo PDF
            
        Returns:
            str: Ruta del archivo PDF generado
        """
        if not output_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"cyberscope_report_{timestamp}.pdf"
        
        if not output_filename.endswith('.pdf'):
            output_filename += '.pdf'
        
        logger.info(f"Generando reporte PDF: {output_filename}")
        
        # Crear documento PDF
        doc = SimpleDocTemplate(
            output_filename,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=3*cm,
            bottomMargin=2*cm
        )
        
        # Contenido del PDF
        story = []
        
        # Página de portada
        story.extend(self.create_cover_page(analysis_data))
        story.append(PageBreak())
        
        # Resumen ejecutivo
        if analysis_data.get('chatgpt_analysis'):
            story.extend(self.create_executive_summary(analysis_data['chatgpt_analysis']))
            story.append(PageBreak())
        
        # Análisis técnico detallado
        story.extend(self.create_technical_analysis_section(analysis_data))
        story.append(PageBreak())
        
        # Análisis ChatGPT (si está disponible)
        if analysis_data.get('chatgpt_analysis'):
            story.extend(self.create_ai_analysis_section(analysis_data['chatgpt_analysis']))
            story.append(PageBreak())
        
        # Hallazgos detallados
        story.extend(self.create_findings_section(analysis_data.get('findings', [])))
        
        # Construir PDF
        try:
            doc.build(story, onFirstPage=self.create_header_footer, onLaterPages=self.create_header_footer)
            logger.info(f"PDF generado exitosamente: {output_filename}")
            return output_filename
        except Exception as e:
            logger.error(f"Error generando PDF: {e}")
            return None

    def create_cover_page(self, analysis_data):
        """Crea la página de portada"""
        elements = []
        
        # Espaciado inicial
        elements.append(Spacer(1, 2*inch))
        
        # Título principal
        elements.append(Paragraph("Reporte de Análisis de Seguridad", self.styles['CyberScopeTitle']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Información del análisis
        target_info = analysis_data.get('target_info', {})
        
        info_data = [
            ['Objetivo:', target_info.get('url', 'N/A')],
            ['Fecha de análisis:', datetime.now().strftime("%d de %B de %Y")],
            ['Tipos de análisis:', ', '.join(target_info.get('analysis_types', []))],
            ['Total de hallazgos:', str(len(analysis_data.get('findings', [])))],
            ['Herramienta:', 'CyberScope v2.0']
        ]
        
        info_table = Table(info_data, colWidths=[3*inch, 3*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f7fafc')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1a365d')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('INNERGRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('BOX', (0, 0), (-1, -1), 2, colors.HexColor('#1a365d')),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f7fafc')])
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 1*inch))
        
        # Nivel de riesgo (si está disponible)
        chatgpt_analysis = analysis_data.get('chatgpt_analysis', {})
        if chatgpt_analysis.get('risk_level'):
            risk_level = chatgpt_analysis['risk_level']
            risk_color = self.get_risk_color(risk_level)
            
            risk_table = Table([['NIVEL DE RIESGO', risk_level]], colWidths=[3*inch, 2*inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#1a365d')),
                ('BACKGROUND', (1, 0), (1, 0), risk_color),
                ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
                ('TEXTCOLOR', (1, 0), (1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 14),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOX', (0, 0), (-1, -1), 2, colors.HexColor('#1a365d'))
            ]))
            
            elements.append(risk_table)
        
        elements.append(Spacer(1, 1*inch))
        
        # Nota legal
        legal_note = """
        <i>Este reporte contiene un análisis automatizado de seguridad realizado por CyberScope v2.0. 
        Los resultados deben ser validados por profesionales de seguridad antes de tomar acciones correctivas.</i>
        """
        elements.append(Paragraph(legal_note, self.styles['Metadata']))
        
        return elements

    def create_executive_summary(self, chatgpt_analysis):
        """Crea el resumen ejecutivo basado en el análisis de ChatGPT"""
        elements = []
        
        elements.append(Paragraph("Resumen Ejecutivo", self.styles['CyberScopeTitle']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Resumen principal
        if chatgpt_analysis.get('executive_summary'):
            elements.append(Paragraph(chatgpt_analysis['executive_summary'], self.styles['ChatGPTAnalysis']))
            elements.append(Spacer(1, 0.2*inch))
        
        # Nivel de riesgo con explicación
        if chatgpt_analysis.get('risk_level'):
            risk_text = f"<b>Nivel de Riesgo Identificado: {chatgpt_analysis['risk_level']}</b>"
            elements.append(Paragraph(risk_text, self.styles['SectionTitle']))
        
        # Hallazgos principales
        if chatgpt_analysis.get('key_findings'):
            elements.append(Paragraph("Hallazgos Principales:", self.styles['SectionTitle']))
            for finding in chatgpt_analysis['key_findings'][:5]:
                elements.append(Paragraph(f"• {finding}", self.styles['NormalFinding']))
        
        return elements

    def create_technical_analysis_section(self, analysis_data):
        """Crea la sección de análisis técnico"""
        elements = []
        
        elements.append(Paragraph("Análisis Técnico Detallado", self.styles['CyberScopeTitle']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Información del objetivo
        target_info = analysis_data.get('target_info', {})
        if target_info:
            elements.append(Paragraph("Información del Objetivo", self.styles['SectionTitle']))
            
            target_data = [
                ['URL/Host:', target_info.get('url', 'N/A')],
                ['Tipos de análisis:', ', '.join(target_info.get('analysis_types', []))],
                ['Timestamp:', target_info.get('timestamp', 'N/A')],
                ['Total de hallazgos:', str(len(analysis_data.get('findings', [])))]
            ]
            
            target_table = Table(target_data, colWidths=[2*inch, 4*inch])
            target_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e2e8f0')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#a0aec0'))
            ]))
            
            elements.append(target_table)
            elements.append(Spacer(1, 0.3*inch))
        
        # Estadísticas de hallazgos
        findings = analysis_data.get('findings', [])
        if findings:
            elements.append(Paragraph("Estadísticas de Hallazgos", self.styles['SectionTitle']))
            
            # Categorizar hallazgos
            categories = self.categorize_findings(findings)
            
            stats_data = [['Categoría', 'Cantidad', 'Porcentaje']]
            total = len(findings)
            
            for category, count in categories.items():
                percentage = f"{(count/total)*100:.1f}%" if total > 0 else "0%"
                stats_data.append([category, str(count), percentage])
            
            stats_table = Table(stats_data, colWidths=[2*inch, 1*inch, 1*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a365d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#1a365d')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')])
            ]))
            
            elements.append(stats_table)
        
        return elements

    def create_ai_analysis_section(self, ai_analysis):
        """Crea la sección de análisis de IA (Groq/Smart Analyzer)"""
        elements = []
        
        # Determinar el tipo de analizador usado
        analyzer_name = ai_analysis.get('analyzer', 'Analizador IA')
        if 'Groq' in analyzer_name:
            title = "Análisis Inteligente (Groq AI)"
        elif 'Smart' in analyzer_name:
            title = "Análisis Inteligente (Smart Analyzer)"
        else:
            title = "Análisis Inteligente"
            
        elements.append(Paragraph(title, self.styles['CyberScopeTitle']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Texto simplificado - CORREGIDO
        if ai_analysis.get('simplified_text'):
            elements.append(Paragraph("Explicacion Simplificada:", self.styles['SectionTitle']))
            
            # Limpiar y procesar el texto
            simplified_text = self.clean_text_for_pdf(ai_analysis.get('simplified_text', ''))
            
            # Dividir en párrafos más pequeños
            paragraphs = self.split_long_text(simplified_text, max_length=600)
            
            for paragraph in paragraphs:
                if paragraph.strip():
                    elements.append(Paragraph(paragraph, self.styles['ChatGPTAnalysis']))
                    elements.append(Spacer(1, 0.1*inch))
        
        # Vulnerabilidades identificadas
        if ai_analysis.get('vulnerabilities'):
            elements.append(Paragraph("Vulnerabilidades Identificadas:", self.styles['SectionTitle']))
            for vuln in ai_analysis['vulnerabilities']:
                clean_vuln = self.clean_text_for_pdf(vuln)
                elements.append(Paragraph(f"• {clean_vuln}", self.styles['CriticalFinding']))
            elements.append(Spacer(1, 0.2*inch))
        
        # Recomendaciones
        if ai_analysis.get('recommendations'):
            elements.append(Paragraph("Recomendaciones:", self.styles['SectionTitle']))
            for rec in ai_analysis['recommendations']:
                clean_rec = self.clean_text_for_pdf(rec)
                elements.append(Paragraph(f"• {clean_rec}", self.styles['Recommendation']))
            elements.append(Spacer(1, 0.2*inch))
        
        # Términos técnicos explicados
        if ai_analysis.get('technical_terms'):
            elements.append(Paragraph("Glosario de Terminos Tecnicos:", self.styles['SectionTitle']))
            for term in ai_analysis['technical_terms']:
                clean_term = self.clean_text_for_pdf(term)
                elements.append(Paragraph(f"• {clean_term}", self.styles['NormalFinding']))
        
        return elements

    def create_findings_section(self, findings):
        """Crea la sección de hallazgos detallados"""
        elements = []
        
        elements.append(Paragraph("Hallazgos Técnicos Detallados", self.styles['CyberScopeTitle']))
        elements.append(Spacer(1, 0.3*inch))
        
        if not findings:
            elements.append(Paragraph("No se encontraron hallazgos técnicos.", self.styles['NormalFinding']))
            return elements
        
        # Categorizar y mostrar hallazgos
        categories = self.categorize_findings_detailed(findings)
        
        for category, category_findings in categories.items():
            if category_findings:
                elements.append(Paragraph(f"{category} ({len(category_findings)} hallazgos)", self.styles['SectionTitle']))
                
                for finding in category_findings:
                    style = self.get_finding_style(finding)
                    elements.append(Paragraph(f"• {finding}", style))
                
                elements.append(Spacer(1, 0.2*inch))
        
        return elements

    def categorize_findings(self, findings):
        """Categoriza hallazgos para estadísticas"""
        categories = {
            'Vulnerabilidades': 0,
            'Información': 0,
            'Configuración': 0,
            'Red': 0,
            'Otros': 0
        }
        
        for finding in findings:
            finding_lower = finding.lower()
            if any(keyword in finding_lower for keyword in ['vuln', 'injection', 'xss', 'rce']):
                categories['Vulnerabilidades'] += 1
            elif any(keyword in finding_lower for keyword in ['info', 'banner', 'version', 'whois']):
                categories['Información'] += 1
            elif any(keyword in finding_lower for keyword in ['header', 'ssl', 'config']):
                categories['Configuración'] += 1
            elif any(keyword in finding_lower for keyword in ['port', 'network', 'ip']):
                categories['Red'] += 1
            else:
                categories['Otros'] += 1
        
        return categories

    def categorize_findings_detailed(self, findings):
        """Categoriza hallazgos para mostrar en detalle"""
        categories = {
            'Vulnerabilidades Críticas': [],
            'Problemas de Configuración': [],
            'Información del Sistema': [],
            'Análisis de Red': [],
            'Otros Hallazgos': []
        }
        
        for finding in findings:
            finding_lower = finding.lower()
            if any(keyword in finding_lower for keyword in ['vuln', 'injection', 'xss', 'rce', 'critical']):
                categories['Vulnerabilidades Críticas'].append(finding)
            elif any(keyword in finding_lower for keyword in ['header', 'ssl', 'config', 'missing']):
                categories['Problemas de Configuración'].append(finding)
            elif any(keyword in finding_lower for keyword in ['info', 'banner', 'version', 'whois', 'meta']):
                categories['Información del Sistema'].append(finding)
            elif any(keyword in finding_lower for keyword in ['port', 'network', 'ip', 'scan']):
                categories['Análisis de Red'].append(finding)
            else:
                categories['Otros Hallazgos'].append(finding)
        
        return categories

    def get_finding_style(self, finding):
        """Determina el estilo basado en el tipo de hallazgo"""
        finding_lower = finding.lower()
        if any(keyword in finding_lower for keyword in ['critical', 'high', 'vuln', 'injection']):
            return self.styles['CriticalFinding']
        else:
            return self.styles['NormalFinding']

    def get_risk_color(self, risk_level):
        """Obtiene el color basado en el nivel de riesgo"""
        colors_map = {
            'Alto': colors.HexColor('#c53030'),
            'Medio': colors.HexColor('#d69e2e'),
            'Bajo': colors.HexColor('#38a169')
        }
        return colors_map.get(risk_level, colors.HexColor('#718096'))
