# app/modules/correlation/rules.py
from typing import List, Dict
from app.core.model import Asset, Finding
from app.core.utils import mk_id, ts

def correlate(assets: List[Asset], local_facts: Dict) -> List[Finding]:
    findings: List[Finding] = []
    ssh_cfg = local_facts.get("ssh_config", "")
    password_auth = False
    if isinstance(ssh_cfg, str):
        # Evaluación in situ para correlación
        from app.modules.local.linux_enum import ssh_password_auth_enabled
        password_auth = ssh_password_auth_enabled(ssh_cfg)

    for asset in assets:
        open_22 = any(p.port == "22" and p.state == "open" for p in asset.ports)
        if open_22 and password_auth:
            findings.append(Finding(
                id=mk_id("finding"),
                timestamp=ts(),
                host_id=asset.host_id(),
                scope="service",
                evidence={"port": "22", "config": "PasswordAuthentication yes"},
                classification={"framework": "CIS/MITRE", "tag": "SSH-Weak-Authentication"},
                risk={"sev": "high", "prob": "medium", "impact": "medium", "vector": "network"},
                recommendation="Deshabilita PasswordAuthentication o restringe por IP; habilita MFA/keys.",
                source_module="correlation.rules",
                trace={"note": "Port 22 open + sshd_config indicates password auth enabled"}
            ))
    return findings