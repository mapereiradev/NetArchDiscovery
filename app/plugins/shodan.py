import os, requests

SEARCH_BACKEND = os.getenv("SHODAN_SEARCH_URL", "http://localhost:3000/search")

def run(target, emit, meta=None):
    """target = cadena de consulta (ej. 'product:Apache')"""
    emit("info", f"Consultando {SEARCH_BACKEND} con query: {target}")
    r = requests.post(SEARCH_BACKEND, json={"query": target}, timeout=30)
    r.raise_for_status()
    data = r.json()
    results = data.get("results", [])
    emit("result", {"query": data.get("query", target), "count": data.get("count", len(results))})
    return data