import subprocess
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

def run_nmap(target):
    try:
        result = subprocess.run(['nmap', '-oX', '-', target],
                                capture_output=True, text=True, check=True)
        formatted_result = parse_nmap_xml(result.stdout)
        # formatted_result = result.stdout
        print(formatted_result)
    except subprocess.CalledProcessError as e:
        print("Error running nmap:")
        print(e.stderr)

if __name__ == "__main__":
    target = input("Enter target (e.g., 192.168.1.1 or example.com): ")
    run_nmap(target)

