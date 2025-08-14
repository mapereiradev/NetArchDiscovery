from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.routes.nmap import caller, parser
from app.modules.acquisition.nmap_acq import scan_network_or_host
from app.modules.local.linux_enum import collect_local_facts
from app.modules.correlation.rules import correlate
from app.modules.reporting.export import assets_to_jsonl, findings_to_jsonl

main = Blueprint("main", __name__)

@main.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@main.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        return render_template("scanning.html")

    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Debe indicar una IP o rango.", "error")
        return redirect(url_for("main.scan"))

    options = []
    if request.form.get("opt_sS"):  # -sS requiere root
        options.append("-sS")
    if request.form.get("opt_sV"):
        options.append("-sV")
    if request.form.get("opt_O"):   # -O requiere root
        options.append("-O")

    try:
      xml_output, meta = caller.run_nmap(target, options)
      if not xml_output:
          flash(f"Error ejecutando nmap: {meta.get('stderr','')}", "error")
          return redirect(url_for("main.scan"))

      results = parser.parse_nmap_xml(xml_output)
      return render_template(
          "scanning.html",
          results=results,
          submitted=True,
          target=target,
          options=" ".join(options),
          meta=meta
      )

    except Exception as e:
        flash(f"Error ejecutando nmap: {e}", "error")
        return redirect(url_for("main.scan"))

@main.route("/analyze", methods=["POST"])
def analyze():
    """
    Flujo integrado: Nmap -> Enum local -> Correlación -> Export
    """
    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Debe indicar una IP o rango.", "error")
        return redirect(url_for("main.scan"))

    options = []
    if request.form.get("opt_sS"):
        options.append("-sS")
    if request.form.get("opt_sV"):
        options.append("-sV")
    if request.form.get("opt_O"):
        options.append("-O")

    # 1) Adquisición
    assets, meta = scan_network_or_host(target, options)

    # 2) Análisis local
    local_facts = collect_local_facts()

    # 3) Correlación
    findings = correlate(assets, local_facts)

    # 4) Export
    assets_jsonl = assets_to_jsonl(assets)
    findings_jsonl = findings_to_jsonl(findings)

    # Además, mostrar también los resultados "bonitos" usando el parser original para la tabla de puertos
    xml_output, _ = caller.run_nmap(target, options)
    pretty_results = parser.parse_nmap_xml(xml_output)

    return render_template(
        "scanning.html",
        results=pretty_results,
        submitted=True,
        target=target,
        options=" ".join(options),
        meta=meta,
        findings=findings,
        assets_jsonl=assets_jsonl,
        findings_jsonl=findings_jsonl,
        local_facts=local_facts
    )