from __future__ import annotations
import ipaddress, socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def _rev(ip: str, timeout: float = 1.5):
    try:
        socket.setdefaulttimeout(timeout)
        name, aliases, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "ptr": name, "aliases": aliases}
    except Exception:
        return {"ip": ip, "ptr": None, "aliases": []}

def _iter_ips_from_target(target: str, max_hosts: int = 256):
    target = (target or "").strip()
    if not target:
        return []
    # IP única
    try:
        ipaddress.IPv4Address(target)
        return [target]
    except Exception:
        pass
    # CIDR
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = [str(h) for h in net.hosts()]
        return hosts[:max_hosts]
    except Exception:
        pass
    # Hostname → resolvemos A y lo tratamos como IP única
    try:
        return [socket.gethostbyname(target)]
    except Exception:
        return []

def run(target: str, emit=print, meta=None):
    meta = meta or {}
    ips = _iter_ips_from_target(target)
    if not ips:
        emit({"warn": "No se han obtenido IPs para DNS inversa"})
        return {"ptrs": [], "count": 0}

    emit({"info": f"PTR sobre {len(ips)} objetivo(s)"})
    out = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(_rev, ip) for ip in ips]
        for f in as_completed(futures):
            r = f.result()
            if r.get("ptr"):
                out.append(r)
                emit({"match": r})

    emit({"summary": f"{len(out)} PTR(s) resueltos"})
    return {"ptrs": out, "count": len(out)}
