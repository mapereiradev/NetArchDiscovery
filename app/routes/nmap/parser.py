import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_text):
    """
    Recibe XML de nmap (-oX -) y devuelve una lista de dispositivos:
    [
      {
        "ip": "192.168.1.10",
        "hostname": "web01.local",
        "os": "Linux 5.X (guess)",   # si hay fingerprint
        "ports": [
          {"port":"22","proto":"tcp","state":"open","service":"ssh","product":"OpenSSH","version":"8.2p1"},
          ...
        ]
      },
      ...
    ]
    """
    if not xml_text or not xml_text.strip():
        return []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # devuelve lista vacía si el XML no es válido
        return []

    hosts_out = []

    for host in root.findall("host"):
        # incluir solo hosts "up" si viene estado
        status = host.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue

        # IP (puede haber varias address; priorizamos ipv4)
        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
                break
        if not ip:
            # si no hay ipv4, cogemos la primera address que haya
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else "Unknown"

        # hostname (si existe)
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "") or ""

        # OS (si existe fingerprint)
        os_name = None
        osmatch = host.find("os/osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name")

        # Puertos (solo abiertos)
        ports_out = []
        for p in host.findall("ports/port"):
            portid = p.get("portid", "")
            proto = p.get("protocol", "tcp")
            st = p.find("state")
            state = st.get("state") if st is not None else ""
            if state != "open":
                continue

            service_node = p.find("service")
            service = service_node.get("name") if service_node is not None else ""
            product = service_node.get("product") if service_node is not None else ""
            version = service_node.get("version") if service_node is not None else ""

            ports_out.append({
                "port": portid,
                "proto": proto,
                "state": state,
                "service": service,
                "product": product,
                "version": version
            })

        hosts_out.append({
            "ip": ip,
            "hostname": hostname,
            "os": os_name,
            "ports": ports_out
        })

    return hosts_out
