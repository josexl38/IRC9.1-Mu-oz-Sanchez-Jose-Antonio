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
    echo "                    Instalador Automático"
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

# Función para leer input del usuario (funciona con curl | bash)
read_user_input() {
    local prompt="$1"
    local default="$2"
    local response
    
    # Redirigir stdin desde /dev/tty para funcionar con pipes
    if [ -t 0 ]; then
        # Terminal interactivo normal
        read -p "$prompt" response
    else
        # Ejecutándose desde pipe (curl | bash)
        echo -n "$prompt"
        read response < /dev/tty
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
        else
            OS="linux"
            DISTRO="Unknown"
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
    
    # Usar la nueva función para leer input
    install_docker_choice=$(read_user_input "¿Instalar Docker? (s/N): " "N")
    
    if [[ $install_docker_choice =~ ^[Ss]$ ]]; then
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
        cat > ~/.ssh/config << EOF
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
    
    mkdir -p uploads reports logs forensic_evidence
    chmod 755 uploads reports logs forensic_evidence
    
    show_success "Directorios creados"
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
        
        # Usar la nueva función para leer input
        web_choice=$(read_user_input "¿Ejecutar interfaz web? (s/N): " "N")
        
        if [[ $web_choice =~ ^[Ss]$ ]]; then
            echo ""
            web_port=$(read_user_input "¿En qué puerto deseas ejecutar la interfaz web? (por defecto 5000): " "5000")
            
            # Modificar docker-compose.yml con el puerto elegido
            if [ -f "docker-compose.yml" ]; then
                sed -i.bak "s/5000:5000/${web_port}:5000/g" docker-compose.yml
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
    
    # Usar la nueva función para leer input
    groq_choice=$(read_user_input "¿Configurar Groq AI? (s/N): " "N")
    
    if [[ $groq_choice =~ ^[Ss]$ ]]; then
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
        if [ -n "$EXTERNAL_IP" ]; then
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
        echo ""
    fi
    
    echo -e "${YELLOW}📁 ARCHIVOS IMPORTANTES:${NC}"
    echo "   cyberscope.log           Log de actividades"
    echo "   reports/                 Reportes generados"
    echo "   uploads/                 Archivos subidos (interfaz web)"
    echo "   forensic_evidence/       Evidencia forense remota"
    echo "   .env                     Configuración de API keys"
    echo ""
    
    echo -e "${GREEN}🎯 CONSEJOS:${NC}"
    echo "   • Usa siempre --pdf o --json para guardar resultados"
    echo "   • Para análisis remoto, prefiere claves SSH sobre contraseñas"
    echo "   • Los análisis remotos no dejan rastros en el servidor objetivo"
    echo "   • Revisa cyberscope.log para detalles de ejecución"
    echo "   • Configura Groq API para análisis inteligente"
    echo ""
    
    if [ "$WEB_ENABLED" = true ]; then
        echo -e "${GREEN}🚀 ACCESO RÁPIDO:${NC}"
        echo -e "   Interfaz Web: ${CYAN}http://localhost:$WEB_PORT${NC}"
        echo ""
    fi
    
    echo -e "${CYAN}============================================================================${NC}"
    echo -e "${GREEN}¡CyberScope v2.0 está listo para usar!${NC}"
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
    
    # Instalación opcional de Docker
    install_docker
    
    # Configuración
    setup_ssh_permissions
    create_directories
    
    # Configuración opcional de interfaz web
    ask_web_interface
    
    # Configuración opcional de IA
    setup_groq_api
    
    # Mostrar ejemplos de uso
    show_usage_examples
}

# Ejecutar función principal
main "$@"
