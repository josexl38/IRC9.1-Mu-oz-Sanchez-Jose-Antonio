# Usar imagen base de Python
FROM python:3.11-slim

# Establecer directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema (INCLUYENDO SSH COMPLETO)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    whois \
    dnsutils \
    netcat-traditional \
    openssh-client \
    openssh-server \
    sshpass \
    net-tools \
    iputils-ping \
    traceroute \
    nmap \
    telnet \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio SSH
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh

# Configurar SSH client para evitar verificación de host
RUN echo "Host *" >> /root/.ssh/config && \
    echo "    StrictHostKeyChecking no" >> /root/.ssh/config && \
    echo "    UserKnownHostsFile=/dev/null" >> /root/.ssh/config && \
    echo "    LogLevel ERROR" >> /root/.ssh/config && \
    chmod 600 /root/.ssh/config

# Copiar archivos de requerimientos
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código de la aplicación
COPY . .

# Crear directorios necesarios
RUN mkdir -p uploads reports templates static logs

# Configurar permisos para SSH
RUN chmod +x /usr/bin/ssh

# Exponer puerto
EXPOSE 5000

# Configurar variables de entorno
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONPATH=/app
ENV SSH_AUTH_SOCK=/tmp/ssh_auth_sock

# Comando de inicio
CMD ["Python", "app.py"]
