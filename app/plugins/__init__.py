from . import nmap as nmap_plugin
from .local import local_enum as local_enum_plugin
from . import dns_reverse as dns_reverse_plugin

def get_available_tools():
    """
    Devuelve un dict nombre→callable que implementa run(target, emit=?, meta=?).
    """
    return {
        "nmap":        lambda target, emit, meta: nmap_plugin.run(target, emit=emit, meta=meta),
        "local_enum":  lambda target, emit, meta: local_enum_plugin.run(target, emit=emit),
        "dns_reverse": lambda target, emit, meta: dns_reverse_plugin.run(target, emit=emit, meta=meta),
    }
