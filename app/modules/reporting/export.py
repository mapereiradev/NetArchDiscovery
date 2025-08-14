# app/modules/reporting/export.py
from typing import List
from app.core.model import Asset, Finding
import json

def assets_to_jsonl(assets: List[Asset]) -> str:
    lines = []
    for a in assets:
        obj = {
            "type": "asset",
            "ip": a.ip,
            "hostname": a.hostname,
            "os": a.os,
            "ports": [{
                "port": p.port, "state": p.state, "service": p.service,
                "proto": p.proto, "product": p.product, "version": p.version
            } for p in a.ports],
            "host_id": a.host_id()
        }
        lines.append(json.dumps(obj, ensure_ascii=False))
    return "\n".join(lines)

def findings_to_jsonl(findings: List[Finding]) -> str:
    return "\n".join([f.to_json() for f in findings])