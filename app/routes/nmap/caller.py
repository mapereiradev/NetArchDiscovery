import subprocess

def run_nmap(target):
    try:
        result = subprocess.run(['nmap', '-oX', '-', target], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return e.stderr
