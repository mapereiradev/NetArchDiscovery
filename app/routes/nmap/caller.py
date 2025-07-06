import subprocess

def run_nmap(target, options=None):
    if options is None:
        options = []

    cmd = ['nmap'] + options + ['-oX', '-', target]
    if '-sS' in options or '-O' in options:
        cmd.insert(0, 'sudo')

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return e.stderr or str(e)

def run_custom_nmap(ip, ports):
    cmd = ["nmap", "-p", ports, "-sCV", ip]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout