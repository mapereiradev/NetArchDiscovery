# app/modules/acquisition/nmap_acq.py
from typing import List, Tuple
from app.routes.nmap import caller, parser
from app.core.model import Asset, PortInfo

def scan_network_or_host(target: str, options: List[str]) -> Tuple[List[Asset], dict]:
    """
    Ejecuta Nmap y devuelve activos normalizados (Asset) y metadatos de ejecución.
    """
    xml_output, meta = caller.run_nmap(target, options)
    parsed = parser.parse_nmap_xml(xml_output)  # devuelve [{'ip','hostname','ports',?os}]
    assets: List[Asset] = []
    for it in parsed:
        ports = [PortInfo(
            port=p['port'],
            state=p['state'],
            service=p.get('service',''),
            proto=p.get('proto','tcp'),
            product=p.get('product',''),
            version=p.get('version','')
        ) for p in it.get('ports', [])]
        assets.append(Asset(ip=it['ip'], hostname=it.get('hostname',''), os=it.get('os'), ports=ports))
    return assets, meta