from .nmap import run as nmap_run
from .local.local_enum import run as local_enum_run

def get_available_tools():
    return {
        "nmap": nmap_run,
        "local_enum": local_enum_run,
    }