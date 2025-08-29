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

## Instalación

Requisitos:
- Python 3.11+
- Docker (para algunos módulos, como Shodan API) 
- Nmap instalado en el sistema

Clonar repositorio:
```bash
git clone https://github.com/tuusuario/NetArchDiscovery.git
cd NetArchDiscovery
