from typing import List
from pathlib import Path
import json

from app.core.model import Asset, Finding


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


def export_results(job, results: dict) -> None:
    """
    Exporta los resultados de un job (assets y findings) a ficheros JSONL en reports/output/
    """
    out_dir = Path("reports/output")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Exportar assets de Nmap (u otros módulos de adquisición)
    if "nmap" in results and "assets" in results["nmap"]:
        assets_jsonl = assets_to_jsonl(results["nmap"]["assets"])
        (out_dir / f"assets_{job.id}.jsonl").write_text(assets_jsonl, encoding="utf-8")

    # Exportar hallazgos correlacionados
    if "findings" in results:
        findings_jsonl = findings_to_jsonl(results["findings"])
        (out_dir / f"findings_{job.id}.jsonl").write_text(findings_jsonl, encoding="utf-8")
