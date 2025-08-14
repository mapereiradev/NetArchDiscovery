# app/modules/local/linux_enum.py
import subprocess
from typing import Dict, Any, List

def _run(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        return out.strip()
    except Exception:
        return ""

def collect_local_facts() -> Dict[str, Any]:
    """
    Enumera datos locales básicos no intrusivos.
    """
    return {
        "users": _run(["cut", "-d:", "-f1", "/etc/passwd"]).splitlines(),
        "suid_bins": _run(["sh", "-lc", "find / -perm -4000 -type f 2>/dev/null | head -n 50"]).splitlines(),
        "ssh_config": _run(["sh", "-lc", "test -f /etc/ssh/sshd_config && cat /etc/ssh/sshd_config || true"]),
    }

def ssh_password_auth_enabled(ssh_config_text: str) -> bool:
    """
    Detecta si PasswordAuthentication está habilitado.
    """
    for line in ssh_config_text.splitlines():
        s = line.strip()
        if s.lower().startswith("passwordauthentication"):
            parts = s.split()
            if len(parts) >= 2 and parts[1].lower() == "yes":
                return True
    return False