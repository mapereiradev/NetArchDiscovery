<<<<<<< HEAD
# Dockerfile
FROM python:3.11-slim

# Paquetes del sistema necesarios para utilidades de red y nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap iproute2 iputils-ping net-tools procps \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copia del código
COPY . /app

=======
FROM python:3.12-slim

# Paquetes del sistema (red + utilidades + git + curl para uv)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap iproute2 iputils-ping net-tools procps \
    git curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Instala UV (gestor de entornos/dep. usado por theHarvester)
# Se instala en /root/.local/bin
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# --- NetArchDiscovery ---
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app

# Se clona a /opt/theHarvester y se sincronizan dependencias en un venv local
RUN git clone https://github.com/laramies/theHarvester /opt/theHarvester \
 && cd /opt/theHarvester \
 && uv sync

# Wrapper para invocar theHarvester desde cualquier lugar:
#   theHarvester ...  ==>  uv run --directory /opt/theHarvester theHarvester ...
RUN printf '#!/bin/sh\nexec uv run --directory /opt/theHarvester theHarvester "$@"\n' \
    > /usr/local/bin/theHarvester && chmod +x /usr/local/bin/theHarvester

>>>>>>> 6ec348e (Entrega TFM: agregar archivos docker)
# Puerto de Flask por defecto
ENV PORT=5000 REPORT_DIR=/app/reports/output
EXPOSE 5000

<<<<<<< HEAD
# Arranque con gunicorn (ajuste app:app al objeto WSGI real)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "run:app"]
=======
# Arranque con gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "run:app"]
>>>>>>> 6ec348e (Entrega TFM: agregar archivos docker)
