# app/plugins/nmap.py
from app.modules.acquisition.nmap_acq import scan_network_or_host

def run(target: str, emit=print):
    """
    Ejecuta Nmap con tu pipeline existente y devuelve resultados normalizados.
    """
    # Opciones por defecto; puedes ajustarlas según tus checkboxes del form
    options = ["-sV"]
    emit({"cmd": f"nmap {' '.join(options)} {target}"})
    assets, meta = scan_network_or_host(target, options)
    # Devuelve un dict serializable
    out = {
        "meta": meta,
        "assets": [
            {
                "ip": a.ip,
                "hostname": a.hostname,
                "os": a.os,
                "ports": [{
                    "port": p.port, "state": p.state, "proto": p.proto,
                    "service": p.service, "product": p.product, "version": p.version
                } for p in a.ports],
            }
            for a in assets
        ],
    }
    emit({"summary": f"{len(out['assets'])} host(s) procesados"})
    return out
