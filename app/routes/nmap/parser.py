import xml.etree.ElementTree as ET

def parse_nmap_xml(file_path):
    root = ET.fromstring(file_path)

    results = []

    for host in root.findall('host'):
        ip = host.find('address').get('addr')
        hostname_elem = host.find('hostnames/hostname')
        hostname = hostname_elem.get('name') if hostname_elem is not None else ''

        ports = []
        for port in host.findall('ports/port'):
            portid = port.get('portid')
            state = port.find('state').get('state')
            service = port.find('service').get('name')
            ports.append({'port': portid, 'state': state, 'service': service})

        results.append({
            'ip': ip,
            'hostname': hostname,
            'ports': ports
        })
    return results