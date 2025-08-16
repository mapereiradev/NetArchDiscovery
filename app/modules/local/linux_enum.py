# app/modules/local/linux_enum.py
from __future__ import annotations
import os, re, shlex, json, stat, pwd, grp, platform, socket
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import subprocess
from shutil import which

# ---------- helpers ----------

def _run(cmd: List[str] | str, timeout: int = 10) -> Tuple[int, str, str]:
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return 127, "", f"{type(e).__name__}: {e}"

def _exists(binname: str) -> bool:
    return which(binname) is not None

def _filemode(mode: int) -> str:
    # estilo ls -l
    is_dir = "d" if stat.S_ISDIR(mode) else "-"
    def triplet(r, w, x):
        return ("r" if mode & r else "-") + ("w" if mode & w else "-") + ("x" if mode & x else "-")
    return is_dir + triplet(0o400,0o200,0o100) + triplet(0o040,0o020,0o010) + triplet(0o004,0o002,0o001)

def _stat(path: str) -> Dict[str, Any]:
    try:
        st = os.stat(path, follow_symlinks=False)
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            owner = st.st_uid
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except Exception:
            group = st.st_gid
        return {
            "path": path,
            "owner": owner,
            "group": group,
            "mode_str": _filemode(st.st_mode),
            "mode_octal": oct(st.st_mode & 0o777),
        }
    except FileNotFoundError:
        return {"path": path, "missing": True}
    except Exception as e:
        return {"path": path, "error": f"{type(e).__name__}: {e}"}

def _read_first(path: str, max_bytes: int = 64_000) -> str:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(max_bytes)
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"

def _parse_ss_listening(ss_out: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for line in ss_out.splitlines():
        # ej: tcp   LISTEN 0      4096        0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=820,fd=3))
        if not line or line.startswith("Netid") or "LISTEN" not in line:
            continue
        try:
            parts = line.split()
            proto = parts[0]
            laddr = parts[-2]  # before last usually
            proc = ""
            pid = None
            m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if m:
                proc, pid = m.group(1), int(m.group(2))
            host, port = laddr.rsplit(":", 1)
            # limpiar IPv6 [::]
            host = host.strip("[]")
            items.append({"proto": proto, "addr": host, "port": int(port), "proc": proc, "pid": pid})
        except Exception:
            pass
    return items

def _parse_sshd_cfg(text: str) -> Dict[str, Optional[str]]:
    opts = {}
    for key in ("PasswordAuthentication", "PermitRootLogin", "PubkeyAuthentication", "X11Forwarding"):
        m = re.search(rf"^\s*{key}\s+(\S+)", text, re.IGNORECASE | re.MULTILINE)
        opts[key] = m.group(1).lower() if m else None
    return opts

# ---------- main collector ----------

KEY_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/root", "/home", "/etc/ssh/sshd_config",
]

SUID_DIRS = ["/bin","/sbin","/usr/bin","/usr/sbin","/usr/local/bin","/usr/local/sbin"]
WORLD_WRITABLE_DIRS = ["/tmp","/var/tmp","/dev/shm"]

def collect_local_facts() -> Dict[str, Any]:
    data: Dict[str, Any] = {}

    # Host
    uname = platform.uname()._asdict()
    data["host"] = {
        "hostname": socket.gethostname(),
        "uname": uname,
    }
    # boot time (best-effort)
    code, out, _ = _run(["who","-b"], timeout=5)
    data["host"]["boot"] = out if code == 0 else None

    # Network
    net: Dict[str, Any] = {"interfaces": [], "routes": [], "resolvers": [], "listening": []}
    # interfaces (ip addr show)
    if _exists("ip"):
        _, addr_out, _ = _run(["ip","-o","addr","show"], timeout=6)
        for line in addr_out.splitlines():
            # 2: eth0    inet 10.0.0.10/24 brd 10.0.0.255 scope global ...
            try:
                _, name, fam, addr = None, None, None, None
                parts = line.split()
                name = parts[1]
                fam = parts[2]
                cidr = parts[3]
                ip = cidr.split("/")[0]
                net["interfaces"].append({"name": name, "family": fam, "addr": ip, "cidr": cidr})
            except Exception:
                pass
    # routes
    if _exists("ip"):
        _, r_out, _ = _run(["ip","route","show"], timeout=5)
        net["routes"] = [l for l in r_out.splitlines() if l.strip()]
    # resolv.conf
    resolv = _read_first("/etc/resolv.conf", 32_000)
    net["resolvers"] = [l for l in resolv.splitlines() if l.strip()]
    # listening sockets
    if _exists("ss"):
        _, ss_out, _ = _run(["ss","-tulpen"], timeout=8)
        net["listening"] = _parse_ss_listening(ss_out)
    else:
        # fallback muy básico con netstat si existiera
        if _exists("netstat"):
            _, ns_out, _ = _run(["netstat","-tulpen"], timeout=8)
            net["listening"] = _parse_ss_listening(ns_out)  # mismo parser funciona para la mayoría

    data["network"] = net

    # Users & groups
    users = [p.pw_name for p in pwd.getpwall() if p.pw_uid >= 0 and p.pw_uid < 65534]
    groups = [g.gr_name for g in grp.getgrall() if g.gr_gid >= 0 and g.gr_gid < 65534]
    sudoers_files = ["/etc/sudoers"] + [str(p) for p in Path("/etc/sudoers.d").glob("*") if p.is_file()]
    sudoers_preview = "\n\n".join([f"## {p}\n{_read_first(p, 4000)}" for p in sudoers_files if os.path.exists(p)])
    data["users"] = {
        "local": users,
        "groups": groups,
        "sudoers": {"files": sudoers_files, "rules_preview": sudoers_preview},
    }

    # Files (permisos clave, SUID en dirs típicos, world-writable)
    key_perm = [_stat(p) for p in KEY_PATHS]
    suid_bins: List[Dict[str, Any]] = []
    if _exists("find"):
        for base in SUID_DIRS:
            if os.path.isdir(base):
                code, out, _ = _run(["bash","-lc", f"find {shlex.quote(base)} -perm -4000 -type f -maxdepth 2 2>/dev/null | head -n 200"], timeout=8)
                for line in out.splitlines()[:200]:
                    suid_bins.append(_stat(line))
    ww_dirs: List[Dict[str, Any]] = []
    for d in WORLD_WRITABLE_DIRS:
        if os.path.isdir(d):
            ww_dirs.append(_stat(d))
    data["files"] = {
        "key_permissions": key_perm,
        "suid_bins": suid_bins,
        "world_writable_dirs": ww_dirs,
    }

    # Services (systemd running)
    services: List[Dict[str, Any]] = []
    if _exists("systemctl"):
        _, svc_out, _ = _run(["systemctl","list-units","--type=service","--state=running","--no-pager","--plain"], timeout=8)
        for line in svc_out.splitlines():
            # ssh.service                  loaded active running OpenBSD Secure Shell server
            m = re.match(r"^(\S+)\s+\S+\s+(\S+)\s+(\S+)", line)
            if m:
                services.append({"name": m.group(1), "load": m.group(2), "state": m.group(3)})
    data["services"] = services

    # Cron
    cron = {"crontab": "", "cron_d": []}
    cron["crontab"] = _read_first("/etc/crontab", 8000)
    cron_d_root = Path("/etc/cron.d")
    if cron_d_root.exists():
        for f in sorted(cron_d_root.glob("*")):
            if f.is_file():
                cron["cron_d"].append({"file": str(f), "content": _read_first(str(f), 4000)})
    data["cron"] = cron

    # Packages (muestra pequeña para no tardar)
    pkg = {"manager": "none", "sample": []}
    if _exists("dpkg-query"):
        pkg["manager"] = "dpkg"
        _, pout, _ = _run(["bash","-lc","dpkg-query -W -f='${Package}\t${Version}\n' | head -n 50"], timeout=7)
        for line in pout.splitlines():
            try:
                n, v = line.split("\t", 1)
                pkg["sample"].append({"name": n, "version": v})
            except ValueError:
                pass
    elif _exists("rpm"):
        pkg["manager"] = "rpm"
        _, pout, _ = _run(["bash","-lc","rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' | head -n 50"], timeout=7)
        for line in pout.splitlines():
            try:
                n, v = line.split("\t", 1)
                pkg["sample"].append({"name": n, "version": v})
            except ValueError:
                pass
    data["packages"] = pkg

    # SSH config audit (si existe)
    ssh_cfg = _read_first("/etc/ssh/sshd_config", 64_000)
    data["ssh_config_audit"] = _parse_sshd_cfg(ssh_cfg)

    return data