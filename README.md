# NetArchDiscovery

NetArchDiscovery es una herramienta modular para **auditoría y monitorización de seguridad en entornos Linux**.  
Integra distintas utilidades de *information gathering* y escaneo en un **flujo de trabajo unificado**, con capacidad de generar informes legibles y exportables a plataformas de monitorización (SIEM, Wazuh, Elastic, Splunk, etc.).

## Características principales

- **Arquitectura modular y extensible** mediante plugins.
- **Sistema de jobs asíncronos** con ejecución concurrente.
- Integración de herramientas populares:
  - [Nmap](https://nmap.org/) → escaneo de red, detección de puertos, servicios y versiones.
  - [TheHarvester](https://github.com/laramies/theHarvester) → recopilación OSINT de dominios, correos y subdominios.
  - [Shodan](https://www.shodan.io/) → búsqueda de dispositivos expuestos en Internet.
  - Escaneo local de la máquina para usuarios, permisos y configuraciones críticas.
- **Reportes automáticos** en:
  - HTML (legible, con hallazgos destacados).
  - JSON/CSV (estructurado, para SIEM/Elastic/Wazuh).
 
## Archivo de entorno
Se necesita crear un archivo .env y colocarlo en el directorio raíz del proyecto con los siguientes datos:

```
FILEPATH_THE_HARVESTER=/tu/directorio/reportes/harvester
OUTPUT_PATH_THE_HARVESTER=//tu/directorio/reportes/
SECRET_KEY=change-m
```

## Instalación

Requisitos:
- Python 3.11+
- Docker (para algunos módulos, como Shodan API) 
- Nmap instalado en el sistema

Clonar repositorio:
```bash
git clone https://github.com/mapereiradev/NetArchDiscovery.git
cd NetArchDiscovery

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python run.py
```
## Arrancar el proyecto
- En local:
  ```bash
  python run.py
  ```
- En Docker:
  ```bash
  docker compose build --no-cache netarch
  docker compose up -d netarch
  docker compose logs -f netarch
  curl http://localhost:5000/health
  ```
