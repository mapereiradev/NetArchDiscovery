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

# Puerto de Flask por defecto
ENV PORT=5000 REPORT_DIR=/app/reports/output
EXPOSE 5000

# Arranque con gunicorn (ajuste app:app al objeto WSGI real)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "run:app"]