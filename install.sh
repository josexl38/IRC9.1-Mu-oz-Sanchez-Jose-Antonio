#!/bin/bash

# ============================================================================
# CyberScope v2.0 - Instalador Automático
# Sistema de Análisis Forense Digital y Pentesting
# ============================================================================

set -e  # Salir si hay errores

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables globales
WEB_ENABLED=false
WEB_PORT=5000
DOCKER_AVAILABLE=false

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "============================================================================"
    echo "   ____      _               ____                           ____  ___  "
    echo "  / ___|   _| |__   ___ _ __/ ___|  ___ ___  _ __   ___  __ |___ \/ _ \ "
    echo " | |  | | | | '_ \ / _ \ '__\___ \ / __/ _ \| '_ \ / _ \ \ \ / / __) | | |"
    echo " | |__| |_| | |_) |  __/ |   ___) | (_| (_) | |_) |  __/  \ V / / __/| |_|"
    echo "  \____\__, |_.__/ \___|_|  |____/ \___\___/| .__/ \___|   \_/ |_____|\___/"
    echo "        |___/                               |_|                           "
    echo ""
    echo "        Sistema de Análisis Forense Digital y Pentesting"
    echo "                    Instalador Automático v2.0"
    echo "============================================================================"
    echo -e "${NC}"
}

# Función para mostrar progreso
show_progress() {
    local message="$1"
    echo -e "${BLUE}[INFO]${NC} $message"
}

# Función para mostrar éxito
show_success() {
    local message="$1"
    echo -e "${GREEN}[✓]${NC} $message"
}

# Función para mostrar advertencia
show_warning() {
    local message="$1"
    echo -e "${YELLOW}[⚠]${NC} $message"
}

# Función para mostrar error
show_error() {
    local message="$1"
    echo -e "${RED}[✗]${NC} $message"
}

# Función para detectar si estamos en modo interactivo
is_interactive() {
    [ -t 0 ] && [ -r /dev/tty ]
}

# Función mejorada para leer input del usuario
read_user_input() {
    local prompt="$1"
    local default="$2"
    local response
    
    echo -n "$prompt"
    
    # Intentar leer desde /dev/tty primero
    if [ -r /dev/tty ]; then
        # Terminal interactivo disponible
        read response < /dev/tty 2>/dev/null || {
            # Si falla, usar el valor por defecto
            show_warning "No se puede leer entrada. Usando valor por defecto: $default"
            response="$default"
            echo "$default"
        }
    else
        # No hay terminal interactivo, usar valor por defecto
        show_warning "Modo no interactivo detectado. Usando valor por defecto: $default"
        response="$default"
        echo "$default"
    fi
    
    # Si está vacío, usar el valor por defecto
    if [ -z "$response" ]; then
        response="$default"
    fi
    
    echo "$response"
}

# Detectar sistema operativo
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            OS="debian"
            DISTRO=$(lsb_release -si 2>/dev/null || echo "Debian")
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
            DISTRO=$(cat /etc/redhat-release | cut -d' ' -f1)
        elif [ -f /etc/arch-release ]; then
            OS="arch"
            DISTRO="Arch Linux"
        else
            OS="linux"
            DISTRO="Unknown Linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macOS"
    else
        OS="unknown"
        DISTRO="Unknown"
    fi
    
    show_progress "Sistema detectado: $DISTRO ($OS)"
}

# Verificar si el usuario es root o tiene sudo
check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        SUDO=""
        show_success "Ejecutándose como root"
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        show_success "Sudo disponible"
    else
        show_error "Se requieren privilegios de administrador (root o sudo)"
        exit 1
    fi
}

# Descargar repositorio si no existe
download_repository() {
    if [ ! -d "IRC9.1-Mu-oz-Sanchez-Jose-Antonio" ]; then
        show_progress "Descargando CyberScope desde GitHub..."
        
        if command -v git >/dev/null 2>&1; then
            git clone https://github.com/josexl38/IRC9.1-Mu-oz-Sanchez-Jose-Antonio.git >/dev/null 2>&1
        else
            show_progress "Git no disponible, instalando..."
            case $OS in
                "debian")
                    $SUDO apt-get update -qq
                    $SUDO apt-get install -y git >/dev/null 2>&1
                    ;;
                "redhat")
                    $SUDO yum install -y git >/dev/null 2>&1
                    ;;
                "arch")
                    $SUDO pacman -S --noconfirm git >/dev/null 2>&1
                    ;;
                "macos")
                    if command -v brew >/dev/null 2>&1; then
                        brew install git >/dev/null 2>&1
                    fi
                    ;;
            esac
            git clone https://github.com/josexl38/IRC9.1-Mu-oz-Sanchez-Jose-Antonio.git >/dev/null 2>&1
        fi
        
        show_success "Repositorio descargado"
    else
        show_success "Repositorio ya existe"
    fi
    
    cd IRC9.1-Mu-oz-Sanchez-Jose-Antonio
}

# Instalar dependencias del sistema
install_system_dependencies() {
    show_progress "Instalando dependencias del sistema..."
    
    case $OS in
        "debian")
            $SUDO apt-get update -qq
            $SUDO apt-get install -y \
                python3 \
                python3-pip \
                python3-venv \
                curl \
                wget \
                whois \
                dnsutils \
                netcat-traditional \
                openssh-client \
                sshpass \
                expect \
                net-tools \
                iputils-ping \
                traceroute \
                telnet \
                git \
                build-essential \
                python3-dev \
                libssl-dev \
                libffi-dev \
                >/dev/null 2>&1
            ;;
        "redhat")
            $SUDO yum update -y -q
            $SUDO yum install -y \
                python3 \
                python3-pip \
                curl \
                wget \
                whois \
                bind-utils \
                nc \
                openssh-clients \
                sshpass \
                expect \
                net-tools \
                iputils \
                traceroute \
                telnet \
                git \
                gcc \
                python3-devel \
                openssl-devel \
                libffi-devel \
                >/dev/null 2>&1
            ;;
        "arch")
            $SUDO pacman -Sy --noconfirm \
                python \
                python-pip \
                curl \
                wget \
                whois \
                bind-tools \
                netcat \
                openssh \
                sshpass \
                expect \
                net-tools \
                iputils \
                traceroute \
                inetutils \
                git \
                base-devel \
                openssl \
                libffi \
                >/dev/null 2>&1
            ;;
        "macos")
            if ! command -v brew >/dev/null 2>&1; then
                show_progress "Instalando Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install python3 curl wget whois openssh sshpass git >/dev/null 2>&1
            ;;
        *)
            show_warning "Sistema operativo no soportado completamente. Intentando instalación básica..."
            ;;
    esac
    
    show_success "Dependencias del sistema instaladas"
}

# Crear entorno virtual de Python
create_python_env() {
    show_progress "Creando entorno virtual de Python..."
    
    if [ -d "cyberscope-env" ]; then
        show_warning "Entorno virtual existente encontrado, eliminando..."
        rm -rf cyberscope-env
    fi
    
    python3 -m venv cyberscope-env
    source cyberscope-env/bin/activate
    
    # Actualizar pip
    pip install --upgrade pip >/dev/null 2>&1
    
    show_success "Entorno virtual creado y activado"
}

# Instalar dependencias de Python
install_python_dependencies() {
    show_progress "Instalando dependencias de Python..."
    
    # Activar entorno virtual
    source cyberscope-env/bin/activate
    
    # Crear requirements.txt básico si no existe
    if [ ! -f "requirements.txt" ]; then
        cat > requirements.txt << 'EOF'
requests>=2.28.0
paramiko>=2.11.0
beautifulsoup4>=4.11.0
cryptography>=3.4.8
Pillow>=9.0.0
PyPDF2>=2.12.0
python-whois>=0.7.3
dnspython>=2.2.1
scapy>=2.4.5
python-nmap>=0.7.1
reportlab>=3.6.0
fpdf2>=2.5.0
colorama>=0.4.4
tabulate>=0.8.9
lxml>=4.6.3
selenium>=4.0.0
python-magic>=0.4.24
hashlib-compat>=1.0.0
ExifRead>=2.3.2
python-dateutil>=2.8.2
urllib3>=1.26.0
certifi>=2021.10.8
chardet>=4.0.0
idna>=3.3
click>=8.0.0
flask>=2.0.0
werkzeug>=2.0.0
jinja2>=3.0.0
markupsafe>=2.0.0
itsdangerous>=2.0.0
gunicorn>=20.1.0
python-dotenv>=0.19.0
groq>=0.3.0
EOF
    fi
    
    # Instalar dependencias principales
    pip install -r requirements.txt >/dev/null 2>&1
    
    show_success "Dependencias de Python instaladas"
}

# Instalar Docker (opcional)
install_docker() {
    show_progress "Verificando Docker..."
    
    if command -v docker >/dev/null 2>&1 && command -v docker-compose >/dev/null 2>&1; then
        show_success "Docker ya está instalado"
        DOCKER_AVAILABLE=true
        return 0
    fi
    
    echo ""
    echo -e "${YELLOW}============================================================================${NC}"
    echo -e "${CYAN}                        INSTALACIÓN DE DOCKER${NC}"
    echo -e "${YELLOW}============================================================================${NC}"
    echo ""
    echo -e "${GREEN}Docker no está instalado.${NC} ¿Deseas instalarlo para usar la interfaz web?"
    echo ""
    echo -e "${CYAN}La interfaz web incluye:${NC}"
    echo "  🌐 Análisis web masivo con múltiples URLs"
    echo "  📁 Análisis forense de archivos"
    echo "  🖥️  Análisis remoto SSH sin rastros"
    echo "  📄 Reportes PDF y JSON descargables"
    echo "  🎯 Interfaz moderna y fácil de usar"
    echo "  🤖 Análisis inteligente con IA"
    echo ""
    echo -e "${YELLOW}Sin Docker solo tendrás acceso a la línea de comandos.${NC}"
    echo ""
    
    # Verificar si estamos en modo interactivo
    if is_interactive; then
        install_docker_choice=$(read_user_input "¿Instalar Docker? (s/N): " "N")
    else
        show_warning "Modo no interactivo: Saltando instalación de Docker"
        show_warning "Para instalar Docker después ejecuta: curl -fsSL https://get.docker.com | bash"
        install_docker_choice="N"
        DOCKER_AVAILABLE=false
        return 1
    fi
    
    if [[ $install_docker_choice =~ ^[SsYy]$ ]]; then
        show_progress "Instalando Docker..."
        
        case $OS in
            "debian")
                # Instalar Docker en Debian/Ubuntu
                curl -fsSL https://get.docker.com -o get-docker.sh
                $SUDO sh get-docker.sh >/dev/null 2>&1
                $SUDO usermod -aG docker $USER >/dev/null 2>&1
                rm get-docker.sh
                
                # Instalar Docker Compose
                $SUDO curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose >/dev/null 2>&1
                $SUDO chmod +x /usr/local/bin/docker-compose
                ;;
            "redhat")
                # Instalar Docker en CentOS/RHEL
                $SUDO yum install -y yum-utils >/dev/null 2>&1
                $SUDO yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null 2>&1
                $SUDO yum install -y docker-ce docker-ce-cli containerd.io >/dev/null 2>&1
                $SUDO systemctl start docker >/dev/null 2>&1
                $SUDO systemctl enable docker >/dev/null 2>&1
                $SUDO usermod -aG docker $USER >/dev/null 2>&1
                
                # Instalar Docker Compose
                $SUDO curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose >/dev/null 2>&1
                $SUDO chmod +x /usr/local/bin/docker-compose
                ;;
            "arch")
                # Instalar Docker en Arch Linux
                $SUDO pacman -S --noconfirm docker docker-compose >/dev/null 2>&1
                $SUDO systemctl start docker >/dev/null 2>&1
                $SUDO systemctl enable docker >/dev/null 2>&1
                $SUDO usermod -aG docker $USER >/dev/null 2>&1
                ;;
            "macos")
                show_warning "En macOS, instala Docker Desktop desde: https://www.docker.com/products/docker-desktop"
                DOCKER_AVAILABLE=false
                return 1
                ;;
        esac
        
        show_success "Docker instalado correctamente"
        show_warning "Nota: Es posible que necesites cerrar sesión y volver a iniciar para usar Docker sin sudo"
        DOCKER_AVAILABLE=true
        return 0
    else
        show_warning "Docker no instalado. Solo estará disponible la versión de línea de comandos."
        DOCKER_AVAILABLE=false
        return 1
    fi
}

# Configurar permisos SSH
setup_ssh_permissions() {
    show_progress "Configurando permisos SSH..."
    
    # Crear directorio SSH si no existe
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    
    # Configurar SSH client
    if [ ! -f ~/.ssh/config ]; then
        cat > ~/.ssh/config << 'EOF'
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile=/dev/null
    LogLevel ERROR
    ConnectTimeout 10
EOF
        chmod 600 ~/.ssh/config
    fi
    
    show_success "Configuración SSH completada"
}

# Crear directorios necesarios
create_directories() {
    show_progress "Creando directorios necesarios..."
    
    mkdir -p uploads reports logs forensic_evidence cyberscope
    chmod 755 uploads reports logs forensic_evidence cyberscope
    
    show_success "Directorios creados"
}

# Crear archivo main.py básico si no existe
create_main_file() {
    if [ ! -f "cyberscope/main.py" ]; then
        show_progress "Creando archivo principal..."
        
        cat > cyberscope/main.py << 'EOF'
#!/usr/bin/env python3
"""
CyberScope v2.0 - Sistema de Análisis Forense Digital y Pentesting
"""

import argparse
import sys
import os

def main():
    parser = argparse.ArgumentParser(
        description='CyberScope v2.0 - Sistema de Análisis Forense Digital y Pentesting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  
ANÁLISIS FORENSE:
  python main.py --hash archivo.txt
  python main.py --exif imagen.jpg --json
  python main.py --pdfmeta documento.pdf
  
ANÁLISIS WEB:
  python main.py --webscan https://ejemplo.com --pdf
  python main.py --vulnscan https://ejemplo.com
  
PENTESTING:
  python main.py --portscan 192.168.1.1 --pdf
  python main.py --pentest https://ejemplo.com --pdf

ANÁLISIS REMOTO SSH:
  python main.py --remotessh --host 192.168.1.100 --user admin --key ~/.ssh/id_rsa --type comprehensive --pdf

OSINT:
  python main.py --whois ejemplo.com
  python main.py --ipinfo 8.8.8.8
        """
    )
    
    # Análisis forense
    parser.add_argument('--hash', help='Calcular hash SHA256 de archivo')
    parser.add_argument('--exif', help='Extraer metadatos EXIF de imagen')
    parser.add_argument('--pdfmeta', help='Extraer metadatos de PDF')
    parser.add_argument('--buscar', help='Buscar archivos sospechosos en directorio')
    parser.add_argument('--ioc', help='Extraer IoCs de archivo de log')
    
    # Análisis web
    parser.add_argument('--webscan', help='Análisis básico de sitio web')
    parser.add_argument('--vulnscan', help='Escaneo de vulnerabilidades web')
    parser.add_argument('--sslcheck', help='Análisis de certificado SSL')
    parser.add_argument('--paramfuzz', help='Fuzzing de parámetros web')
    
    # Pentesting
    parser.add_argument('--portscan', help='Escaneo de puertos')
    parser.add_argument('--pentest', help='Pentesting completo')
    
    # Análisis remoto SSH
    parser.add_argument('--remotessh', action='store_true', help='Análisis remoto SSH')
    parser.add_argument('--host', help='Host remoto para análisis SSH')
    parser.add_argument('--user', help='Usuario SSH')
    parser.add_argument('--password', help='Contraseña SSH')
    parser.add_argument('--key', help='Archivo de clave SSH privada')
    parser.add_argument('--type', choices=['comprehensive', 'vulnerability', 'forensic'], 
                       default='comprehensive', help='Tipo de análisis remoto')
    
    # OSINT
    parser.add_argument('--whois', help='Información WHOIS de dominio')
    parser.add_argument('--ipinfo', help='Información de dirección IP')
    
    # Formatos de salida
    parser.add_argument('--pdf', action='store_true', help='Generar reporte PDF')
    parser.add_argument('--json', action='store_true', help='Generar reporte JSON')
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    print("🔧 CyberScope v2.0 - Sistema en desarrollo")
    print("📋 Para funcionalidad completa, usa la interfaz web con Docker")
    print("🌐 Ejecuta: docker-compose up -d")
    print("")
    
    # Implementación básica
    if args.hash:
        print(f"🔍 Calculando hash de: {args.hash}")
    elif args.webscan:
        print(f"🌐 Analizando sitio web: {args.webscan}")
    elif args.remotessh:
        if not args.host:
            print("❌ Error: --host es requerido para análisis SSH")
            return
        print(f"🖥️ Análisis SSH remoto en: {args.host}")
    else:
        print("ℹ️ Funcionalidad en desarrollo...")

if __name__ == "__main__":
    main()
EOF
        
        chmod +x cyberscope/main.py
        show_success "Archivo principal creado"
    fi
}

# Preguntar sobre interfaz web
ask_web_interface() {
    if [ "$DOCKER_AVAILABLE" = true ]; then
        echo ""
        echo -e "${YELLOW}============================================================================${NC}"
        echo -e "${CYAN}                        CONFIGURACIÓN DE INTERFAZ WEB${NC}"
        echo -e "${YELLOW}============================================================================${NC}"
        echo ""
        echo -e "${GREEN}Docker está disponible.${NC} ¿Deseas ejecutar la interfaz web ahora?"
        echo ""
        echo -e "${CYAN}La interfaz web incluye:${NC}"
        echo "  🌐 Análisis web masivo con múltiples URLs"
        echo "  📁 Análisis forense de archivos"
        echo "  🖥️  Análisis remoto SSH sin rastros"
        echo "  📄 Reportes PDF y JSON descargables"
        echo "  🎯 Interfaz moderna y fácil de usar"
        echo "  🤖 Análisis inteligente con IA (Groq)"
        echo ""
        
        # Verificar si estamos en modo interactivo
        if is_interactive; then
            web_choice=$(read_user_input "¿Ejecutar interfaz web? (s/N): " "N")
        else
            show_warning "Modo no interactivo: No iniciando interfaz web automáticamente"
            show_warning "Para iniciar después ejecuta: docker-compose up -d"
            web_choice="N"
            WEB_ENABLED=false
            return 1
        fi
        
        if [[ $web_choice =~ ^[SsYy]$ ]]; then
            echo ""
            if is_interactive; then
                web_port=$(read_user_input "¿En qué puerto deseas ejecutar la interfaz web? (por defecto 5000): " "5000")
            else
                web_port="5000"
                show_warning "Usando puerto por defecto: 5000"
            fi
            
            # Crear docker-compose.yml básico si no existe
            if [ ! -f "docker-compose.yml" ]; then
                cat > docker-compose.yml << EOF
version: '3.8'
services:
  cyberscope:
    build: .
    ports:
      - "${web_port}:5000"
    volumes:
      - ./uploads:/app/uploads
      - ./reports:/app/reports
      - ./logs:/app/logs
      - ./forensic_evidence:/app/forensic_evidence
    environment:
      - FLASK_ENV=production
      - GROQ_API_KEY=\${GROQ_API_KEY:-}
    restart: unless-stopped
EOF
            fi
            
            # Crear Dockerfile básico si no existe
            if [ ! -f "Dockerfile" ]; then
                cat > Dockerfile << 'EOF'
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
EOF
            fi
            
            show_progress "Construyendo contenedor Docker..."
            docker-compose build >/dev/null 2>&1
            
            show_progress "Iniciando interfaz web en puerto $web_port..."
            docker-compose up -d >/dev/null 2>&1
            
            # Esperar a que el servicio esté listo
            sleep 8
            
            if docker-compose ps | grep -q "Up"; then
                show_success "Interfaz web iniciada correctamente"
                echo ""
                echo -e "${GREEN}🌐 Interfaz web disponible en:${NC}"
                echo -e "${CYAN}   http://localhost:$web_port${NC}"
                
                # Intentar obtener IP externa
                EXTERNAL_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || curl -s ifconfig.me 2>/dev/null || echo "TU_IP")
                if [ "$EXTERNAL_IP" != "TU_IP" ]; then
                    echo -e "${CYAN}   http://$EXTERNAL_IP:$web_port${NC}"
                fi
                echo ""
                WEB_ENABLED=true
                WEB_PORT=$web_port
            else
                show_error "Error iniciando la interfaz web"
                echo "Logs del contenedor:"
                docker-compose logs
                WEB_ENABLED=false
            fi
        else
            show_warning "Interfaz web no iniciada"
            WEB_ENABLED=false
        fi
    else
        show_warning "Docker no disponible. Solo estará disponible la versión de línea de comandos."
        WEB_ENABLED=false
    fi
}

# Configurar API de Groq (opcional)
setup_groq_api() {
    echo ""
    echo -e "${YELLOW}============================================================================${NC}"
    echo -e "${CYAN}                        CONFIGURACIÓN DE IA (GROQ)${NC}"
    echo -e "${YELLOW}============================================================================${NC}"
    echo ""
    echo -e "${GREEN}¿Deseas configurar análisis inteligente con IA?${NC}"
    echo ""
    echo -e "${CYAN}Groq AI es GRATUITO y proporciona:${NC}"
    echo "  🤖 Análisis inteligente de hallazgos técnicos"
    echo "  📊 Evaluación automática de riesgos"
    echo "  💡 Recomendaciones específicas de seguridad"
    echo "  📝 Explicaciones comprensibles para usuarios no técnicos"
    echo ""
    echo -e "${YELLOW}Para obtener API key gratuita:${NC}"
    echo "  1. Ve a: https://console.groq.com"
    echo "  2. Regístrate con tu email (gratis)"
    echo "  3. Crea una API Key"
    echo "  4. Copia la key (empieza con 'gsk_')"
    echo ""
    
    # Verificar si estamos en modo interactivo
    if is_interactive; then
        groq_choice=$(read_user_input "¿Configurar Groq AI? (s/N): " "N")
    else
        show_warning "Modo no interactivo: Saltando configuración de Groq AI"
        show_warning "Para configurar después: echo 'GROQ_API_KEY=gsk_tu_key' > .env"
        groq_choice="N"
        echo "# GROQ_API_KEY=gsk_tu_api_key_aqui" > .env
        return 1
    fi
    
    if [[ $groq_choice =~ ^[SsYy]$ ]]; then
        echo ""
        groq_api_key=$(read_user_input "Ingresa tu API key de Groq (gsk_...): " "")
        
        if [[ $groq_api_key =~ ^gsk_ ]]; then
            echo "GROQ_API_KEY=$groq_api_key" > .env
            show_success "API key de Groq configurada"
            
            # Si Docker está corriendo, reiniciar para aplicar cambios
            if [ "$WEB_ENABLED" = true ]; then
                show_progress "Reiniciando interfaz web con IA habilitada..."
                docker-compose restart >/dev/null 2>&1
                sleep 3
                show_success "Interfaz web reiniciada con IA"
            fi
        else
            show_warning "API key inválida. Debe empezar con 'gsk_'"
            show_warning "Puedes configurarla después editando el archivo .env"
        fi
    else
        show_warning "IA no configurada. CyberScope usará analizador de respaldo"
        echo "# GROQ_API_KEY=gsk_tu_api_key_aqui" > .env
    fi
}

# Mostrar ejemplos de uso
show_usage_examples() {
    echo ""
    echo -e "${CYAN}"
    echo "============================================================================"
    echo "                           CYBERSCOPE v2.0 INSTALADO"
    echo "============================================================================"
    echo -e "${NC}"
    
    echo -e "${GREEN}✓ Instalación completada exitosamente${NC}"
    echo ""
    
    if [ "$WEB_ENABLED" = true ]; then
        echo -e "${PURPLE}🌐 INTERFAZ WEB DISPONIBLE:${NC}"
        echo -e "   ${CYAN}http://localhost:$WEB_PORT${NC}"
        
        # Mostrar IP externa si está disponible
        EXTERNAL_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "")
        if [ -n "$EXTERNAL_IP" ] && [ "$EXTERNAL_IP" != "127.0.0.1" ]; then
            echo -e "   ${CYAN}http://$EXTERNAL_IP:$WEB_PORT${NC}"
        fi
        echo ""
        echo -e "${YELLOW}Características de la interfaz web:${NC}"
        echo "   🌐 Análisis web masivo de múltiples URLs"
        echo "   📁 Análisis forense de archivos (hash, EXIF, PDF, IoCs)"
        echo "   🖥️  Análisis remoto SSH sin dejar rastros"
        echo "   📄 Reportes PDF y JSON profesionales"
        echo "   🎯 Progreso en tiempo real"
        echo "   🤖 Análisis inteligente con IA"
        echo ""
    fi
    
    echo -e "${PURPLE}📋 LÍNEA DE COMANDOS:${NC}"
    echo ""
    echo -e "${YELLOW}Para usar CyberScope desde línea de comandos:${NC}"
    echo -e "${CYAN}cd $(pwd)${NC}"
    echo -e "${CYAN}source cyberscope-env/bin/activate${NC}  # Activar entorno virtual"
    echo -e "${CYAN}cd cyberscope${NC}"
    echo -e "${CYAN}python main.py --help${NC}  # Ver todas las opciones"
    echo ""
    
    echo -e "${YELLOW}📚 EJEMPLOS DE USO:${NC}"
    echo ""
    
    echo -e "${GREEN}🔍 ANÁLISIS FORENSE:${NC}"
    echo -e "${CYAN}python main.py --hash archivo.txt${NC}                    # Hash de archivo"
    echo -e "${CYAN}python main.py --buscar /ruta/directorio --pdf${NC}       # Buscar archivos sospechosos"
    echo -e "${CYAN}python main.py --exif imagen.jpg --json${NC}              # Metadatos EXIF"
    echo -e "${CYAN}python main.py --pdfmeta documento.pdf${NC}               # Metadatos PDF"
    echo -e "${CYAN}python main.py --ioc log.txt --pdf${NC}                   # Extraer IoCs"
    echo ""
    
    echo -e "${GREEN}🌐 ANÁLISIS WEB:${NC}"
    echo -e "${CYAN}python main.py --webscan https://ejemplo.com --pdf${NC}   # Análisis web básico"
    echo -e "${CYAN}python main.py --vulnscan https://ejemplo.com${NC}        # Vulnerabilidades web"
    echo -e "${CYAN}python main.py --sslcheck ejemplo.com${NC}                # Análisis SSL"
    echo -e "${CYAN}python main.py --paramfuzz https://ejemplo.com/search${NC} # Fuzzing parámetros"
    echo ""
    
    echo -e "${GREEN}🔧 PENTESTING:${NC}"
    echo -e "${CYAN}python main.py --portscan 192.168.1.1 --pdf${NC}         # Escaneo de puertos"
    echo -e "${CYAN}python main.py --pentest https://ejemplo.com --pdf${NC}   # Pentesting completo"
    echo ""
    
    echo -e "${GREEN}🖥️ ANÁLISIS REMOTO SSH:${NC}"
    echo -e "${CYAN}python main.py --remotessh --host 192.168.1.100 \\${NC}"
    echo -e "${CYAN}               --user admin --key ~/.ssh/id_rsa \\${NC}"
    echo -e "${CYAN}               --type comprehensive --pdf --json${NC}     # Análisis forense remoto"
    echo ""
    echo -e "${CYAN}python main.py --remotessh --host servidor.com \\${NC}"
    echo -e "${CYAN}               --user root --password mi_pass \\${NC}"
    echo -e "${CYAN}               --type vulnerability --pdf${NC}            # Solo vulnerabilidades"
    echo ""
    echo -e "${CYAN}python main.py --remotessh --host 10.0.0.50 \\${NC}"
    echo -e "${CYAN}               --user forensic --key /home/user/.ssh/id_ed25519 \\${NC}"
    echo -e "${CYAN}               --type forensic --json${NC}                # Análisis forense específico"
    echo ""
    
    echo -e "${GREEN}🔗 OSINT:${NC}"
    echo -e "${CYAN}python main.py --whois ejemplo.com${NC}                   # Información WHOIS"
    echo -e "${CYAN}python main.py --ipinfo 8.8.8.8${NC}                     # Información de IP"
    echo ""
    
    if [ "$WEB_ENABLED" = true ]; then
        echo -e "${YELLOW}🐳 COMANDOS DOCKER:${NC}"
        echo -e "${CYAN}docker-compose logs -f${NC}                           # Ver logs en tiempo real"
        echo -e "${CYAN}docker-compose stop${NC}                              # Detener servicio"
        echo -e "${CYAN}docker-compose start${NC}                             # Iniciar servicio"
        echo -e "${CYAN}docker-compose restart${NC}                           # Reiniciar servicio"
        echo -e "${CYAN}docker-compose down${NC}                              # Detener y eliminar contenedores"
        echo ""
    fi
    
    echo -e "${YELLOW}📁 ESTRUCTURA DE ARCHIVOS:${NC}"
    echo "   📂 $(pwd)/"
    echo "   ├── 📁 cyberscope/              # Código principal"
    echo "   │   └── 📄 main.py              # Script principal CLI"
    echo "   ├── 📁 cyberscope-env/          # Entorno virtual Python"
    echo "   ├── 📁 reports/                 # Reportes generados"
    echo "   ├── 📁 uploads/                 # Archivos subidos (interfaz web)"
    echo "   ├── 📁 logs/                    # Logs de actividades"
    echo "   ├── 📁 forensic_evidence/       # Evidencia forense remota"
    echo "   ├── 📄 .env                     # Configuración de API keys"
    echo "   ├── 📄 requirements.txt         # Dependencias Python"
    echo "   ├── 📄 docker-compose.yml       # Configuración Docker"
    echo "   └── 📄 Dockerfile               # Imagen Docker"
    echo ""
    
    echo -e "${GREEN}🎯 CONSEJOS IMPORTANTES:${NC}"
    echo "   • Siempre activa el entorno virtual antes de usar CLI"
    echo "   • Usa --pdf o --json para guardar resultados importantes"
    echo "   • Para análisis remotos, prefiere claves SSH sobre contraseñas"
    echo "   • Los análisis remotos SSH no dejan rastros en el servidor objetivo"
    echo "   • Revisa logs/ para detalles de ejecución"
    echo "   • Configura Groq API para análisis inteligente gratuito"
    echo "   • La interfaz web es más completa que la línea de comandos"
    echo ""
    
    echo -e "${PURPLE}🔧 CONFIGURACIÓN ADICIONAL:${NC}"
    echo ""
    echo -e "${YELLOW}1. Para configurar Groq AI después:${NC}"
    echo -e "${CYAN}   echo 'GROQ_API_KEY=gsk_tu_api_key' > .env${NC}"
    echo ""
    echo -e "${YELLOW}2. Para actualizar CyberScope:${NC}"
    echo -e "${CYAN}   git pull origin main${NC}"
    echo -e "${CYAN}   source cyberscope-env/bin/activate${NC}"
    echo -e "${CYAN}   pip install -r requirements.txt --upgrade${NC}"
    echo ""
    echo -e "${YELLOW}3. Para reinstalar Docker después:${NC}"
    echo -e "${CYAN}   curl -fsSL https://get.docker.com | bash${NC}"
    echo -e "${CYAN}   sudo usermod -aG docker \$USER${NC}"
    echo ""
    
    if [ "$WEB_ENABLED" = true ]; then
        echo -e "${GREEN}🚀 ACCESO RÁPIDO:${NC}"
        echo -e "   🌐 Interfaz Web: ${CYAN}http://localhost:$WEB_PORT${NC}"
        
        # Mostrar IP externa si está disponible
        EXTERNAL_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "")
        if [ -n "$EXTERNAL_IP" ] && [ "$EXTERNAL_IP" != "127.0.0.1" ]; then
            echo -e "   🌍 Acceso externo: ${CYAN}http://$EXTERNAL_IP:$WEB_PORT${NC}"
        fi
        echo ""
    else
        echo -e "${YELLOW}💡 PARA HABILITAR INTERFAZ WEB:${NC}"
        echo -e "   1. Instala Docker: ${CYAN}curl -fsSL https://get.docker.com | bash${NC}"
        echo -e "   2. Reinicia sesión o ejecuta: ${CYAN}newgrp docker${NC}"
        echo -e "   3. Ejecuta: ${CYAN}docker-compose up -d${NC}"
        echo ""
    fi
    
    echo -e "${PURPLE}🛡️ TIPOS DE ANÁLISIS REMOTO SSH:${NC}"
    echo ""
    echo -e "${GREEN}comprehensive${NC} - Análisis completo del sistema:"
    echo "   • Información del sistema y hardware"
    echo "   • Procesos y servicios en ejecución"
    echo "   • Usuarios y grupos"
    echo "   • Conexiones de red"
    echo "   • Archivos de configuración críticos"
    echo "   • Logs del sistema"
    echo "   • Análisis forense básico"
    echo ""
    echo -e "${GREEN}vulnerability${NC} - Enfoque en vulnerabilidades:"
    echo "   • Escaneo de puertos internos"
    echo "   • Servicios con vulnerabilidades conocidas"
    echo "   • Configuraciones inseguras"
    echo "   • Permisos incorrectos de archivos"
    echo "   • Usuarios con privilegios elevados"
    echo ""
    echo -e "${GREEN}forensic${NC} - Análisis forense específico:"
    echo "   • Artefactos del sistema"
    echo "   • Líneas de tiempo de archivos"
    echo "   • Análisis de memoria (si es posible)"
    echo "   • Hashes de archivos críticos"
    echo "   • Evidencia de compromiso"
    echo ""
    
    # Mostrar comandos específicos según el modo
    if ! is_interactive; then
        echo -e "${YELLOW}🤖 MODO NO INTERACTIVO DETECTADO:${NC}"
        echo ""
        echo -e "${GREEN}Para usar todas las funcionalidades:${NC}"
        echo ""
        echo -e "${CYAN}# Instalar Docker:${NC}"
        echo -e "${CYAN}curl -fsSL https://get.docker.com | bash${NC}"
        echo -e "${CYAN}sudo usermod -aG docker \$USER${NC}"
        echo -e "${CYAN}newgrp docker${NC}"
        echo ""
        echo -e "${CYAN}# Iniciar interfaz web:${NC}"
        echo -e "${CYAN}cd $(pwd)${NC}"
        echo -e "${CYAN}docker-compose up -d${NC}"
        echo ""
        echo -e "${CYAN}# Configurar IA:${NC}"
        echo -e "${CYAN}echo 'GROQ_API_KEY=gsk_tu_api_key' > .env${NC}"
        echo -e "${CYAN}docker-compose restart${NC}"
        echo ""
    fi
    
    echo -e "${CYAN}============================================================================${NC}"
    echo -e "${GREEN}✅ ¡CyberScope v2.0 está completamente instalado y listo para usar!${NC}"
    echo ""
    echo -e "${YELLOW}📖 Documentación completa: ${CYAN}https://github.com/josexl38/IRC9.1-Mu-oz-Sanchez-Jose-Antonio${NC}"
    echo -e "${YELLOW}🐛 Reportar issues: ${CYAN}https://github.com/josexl38/IRC9.1-Mu-oz-Sanchez-Jose-Antonio/issues${NC}"
    echo -e "${CYAN}============================================================================${NC}"
}

# Función principal
main() {
    print_banner
    
    # Verificaciones iniciales
    detect_os
    check_privileges
    
    # Descargar repositorio si no existe
    download_repository
    
    # Instalación
    install_system_dependencies
    create_python_env
    install_python_dependencies
    
    # Crear archivos básicos
    create_directories
    create_main_file
    
    # Instalación opcional de Docker
    install_docker
    
    # Configuración
    setup_ssh_permissions
    
    # Configuración opcional de interfaz web
    ask_web_interface
    
    # Configuración opcional de IA
    setup_groq_api
    
    # Mostrar ejemplos de uso
    show_usage_examples
}

# Ejecutar función principal
main "$@"
