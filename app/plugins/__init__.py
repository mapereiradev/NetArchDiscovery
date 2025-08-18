from __future__ import annotations

from . import nmap as nmap_plugin
from app.modules.local import linux_enum as local_enum_plugin
from . import dns_reverse as dns_reverse_plugin  # ← NUEVO

def get_available_tools():
    """Devuelve un dict nombre→callable que implementa run(target, emit=?, meta=?)."""
    return {
        "nmap":        lambda target, emit, meta: nmap_plugin.run(target, emit=emit, meta=meta),
        "local_enum":  lambda target, emit, meta: local_enum_plugin.run(target=target, emit=emit, meta=meta),
        "dns_reverse": lambda target, emit, meta: dns_reverse_plugin.run(target, emit=emit, meta=meta),  # ← NUEVO
    }
