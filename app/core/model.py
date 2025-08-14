# app/core/model.py
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
import json
import hashlib

@dataclass
class PortInfo:
    port: str
    state: str
    service: str = ""
    proto: str = "tcp"
    product: str = ""
    version: str = ""

@dataclass
class Asset:
    ip: str
    hostname: str = ""
    os: Optional[str] = None
    ports: List[PortInfo] = field(default_factory=list)

    def host_id(self) -> str:
        return hashlib.sha256(self.ip.encode()).hexdigest()[:16]

@dataclass
class Finding:
    id: str
    timestamp: str
    host_id: str
    scope: str                 # "network" | "host" | "service" | "file"
    evidence: Dict            # e.g., {"port": "22", "banner": "..."}
    classification: Dict      # e.g., {"framework": "CIS/MITRE", "tag": "SSH-Weak-Config"}
    risk: Dict                # e.g., {"sev":"high","prob":"med","impact":"med","vector":"network"}
    recommendation: str
    source_module: str
    trace: Dict               # e.g., {"command": "cat /etc/ssh/sshd_config"}

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)