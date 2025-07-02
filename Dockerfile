# Imagen base oficial con Python
FROM python:3.11-slim

# Instalar dependencias del sistema
RUN apt-get update && \
    apt-get install -y \
        nmap \
        sudo \
    && rm -rf /var/lib/apt/lists/*

# Crear usuario appuser con bash y sin password
RUN useradd -ms /bin/bash appuser

# Dar permisos sudo a appuser para nmap sin password
RUN echo "appuser ALL=(ALL) NOPASSWD: /usr/bin/nmap" >> /etc/sudoers

# Establecer directorio de trabajo
WORKDIR /app

# Copiar archivos de requirements.txt e instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto de tu proyecto
COPY . .

# Cambiar a usuario appuser
USER appuser

# Exponer el puerto Flask
EXPOSE 5000

# Ejecutar la aplicación
CMD ["python", "run.py"]
