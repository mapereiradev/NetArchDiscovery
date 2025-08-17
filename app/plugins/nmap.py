from app.modules.acquisition.nmap_acq import scan_network_or_host

def run(target: str, emit=print, meta=None):
    meta = meta or {}
    extra = meta.get("nmap_opts") or []   # ← llega desde /api/scan
    # por defecto -sV, y añade extras sin duplicar
    opts = ["-sV"] + [o for o in extra if o not in ("-sV",)]
    emit({"cmd": f"nmap {' '.join(opts)} {target}".strip()})
    assets, meta_out = scan_network_or_host(target, opts)
    out = {
        "meta": meta_out,
        "assets": [
            {
                "ip": a.get("ip") if isinstance(a, dict) else getattr(a, "ip", None),
                "hostname": a.get("hostname") if isinstance(a, dict) else getattr(a, "hostname", None),
                "os": a.get("os") if isinstance(a, dict) else getattr(a, "os", None),
                "ports": [
                    {
                        "port": p.get("port") if isinstance(p, dict) else getattr(p, "port", None),
                        "state": p.get("state") if isinstance(p, dict) else getattr(p, "state", None),
                        "proto": p.get("proto") if isinstance(p, dict) else getattr(p, "proto", "tcp"),
                        "service": p.get("service") if isinstance(p, dict) else getattr(p, "service", None),
                        "product": p.get("product") if isinstance(p, dict) else getattr(p, "product", None),
                        "version": p.get("version") if isinstance(p, dict) else getattr(p, "version", None),
                    } for p in (a.get("ports", []) if isinstance(a, dict) else getattr(a, "ports", []))
                ],
            }
            for a in assets
        ],
    }
    emit({"summary": f"{len(out['assets'])} host(s) procesados"})
    return out
