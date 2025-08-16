# app/plugins/local_enum.py
from app.modules.local.linux_enum import collect_local_facts

def run(_target_ignored: str = "", emit=print):
    emit("Enumerando sistema local…")
    data = collect_local_facts()
    # avisos rápidos (mini-auditoría)
    ssh = data.get("ssh_config_audit", {})
    if ssh.get("PasswordAuthentication") in ("yes", "true"):
        emit({"warn": "SSH permite autenticación por contraseña"})
    if ssh.get("PermitRootLogin") not in (None, "no", "prohibit-password"):
        emit({"warn": f"PermitRootLogin={ssh.get('PermitRootLogin')}"})
    suid_count = len(data.get("files", {}).get("suid_bins", []))
    if suid_count > 0:
        emit({"info": f"SUID encontrados: {suid_count}"})
    emit("Enumeración local completada")
    return data
