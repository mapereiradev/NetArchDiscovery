# app/modules/correlation/rules.py
from __future__ import annotations
from typing import Dict, Any, List

def _each_host(nmap: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not nmap or "assets" not in nmap:
        return []
    return nmap["assets"]

def run_rules(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Aplica reglas simples sobre resultados agregados del job.
    Devuelve {"findings":[...]}.
    """
    findings: List[Dict[str, Any]] = []

    nmap = results.get("nmap")
    local = results.get("local_enum") or {}

    # ---- Regla 1: SSH con password habilitada y 22/tcp expuesto
    ssh_cfg = (local.get("ssh_config_audit") or {})
    ssh_pw = ssh_cfg.get("PasswordAuthentication")
    if ssh_pw in ("yes", "true"):
        for h in _each_host(nmap):
            for p in h.get("ports", []):
                if str(p.get("port")) == "22" and (p.get("state") in ("open", None)):
                    findings.append({
                        "id": "SSH-PA-001",
                        "severity": "medium",
                        "title": "SSH permite autenticación por contraseña",
                        "evidence": {"host": h.get("ip"), "PasswordAuthentication": ssh_pw},
                    })
                    break

    # ---- Regla 2: Servicios inseguros (telnet/ftp) abiertos
    INSECURE = {"23": "telnet", "21": "ftp"}
    for h in _each_host(nmap):
        for p in h.get("ports", []):
            port = str(p.get("port"))
            if port in INSECURE and (p.get("state") in ("open", None)):
                findings.append({
                    "id": f"INSECURE-{port}",
                    "severity": "high",
                    "title": f"Servicio inseguro expuesto: {INSECURE[port]}",
                    "evidence": {"host": h.get("ip"), "port": port},
                })

    # ---- Regla 3: Exposición amplia (0.0.0.0) en servicios comunes
    WILDCARD_PORTS = {"22", "80", "443", "3389", "5900"}
    listening = (local.get("network") or {}).get("listening") or []
    for s in listening:
        if str(s.get("port")) in WILDCARD_PORTS and s.get("addr") in ("0.0.0.0", "::"):
            findings.append({
                "id": "WILDCARD-BIND",
                "severity": "medium",
                "title": "Servicio crítico escuchando en todas las interfaces",
                "evidence": {"addr": s.get("addr"), "port": s.get("port"), "proc": s.get("proc")},
            })

    # ---- Regla 4: Mucho SUID (indicativo de superficie)
    suid_bins = (local.get("files") or {}).get("suid_bins") or []
    if len(suid_bins) >= 15:
        findings.append({
            "id": "SUID-MANY",
            "severity": "low",
            "title": f"Número elevado de binarios SUID",
            "evidence": {"count": len(suid_bins)},
        })

    # ---- Regla 5: DNS externos (informativa)
    resolvers = (local.get("network") or {}).get("resolvers") or []
    externals = [l for l in resolvers if l.strip().startswith("nameserver ")]
    if externals:
        findings.append({
            "id": "DNS-RESOLVERS",
            "severity": "info",
            "title": "Servidores DNS configurados",
            "evidence": {"resolvers": externals[:5]},
        })

    return {"findings": findings}
s