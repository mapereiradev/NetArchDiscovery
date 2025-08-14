import subprocess
import shlex

# Opciones que requieren root
ROOT_REQUIRED_FLAGS = {"-sS", "-O", "-A"}

def run_nmap(target, extra_args=None):
    """
    Ejecuta nmap con opciones dinámicas y salida XML.
    :param target: IP o red
    :param extra_args: lista de opciones adicionales (ej: ["-sS", "-sV"])
    :return: (xml_output:str, meta:dict)
    """
    if extra_args is None:
        extra_args = []

    # Verificar si se requiere root
    needs_root = any(opt in ROOT_REQUIRED_FLAGS for opt in extra_args)

    # Construir comando
    cmd = ["nmap"] + extra_args + ["-oX", "-", target]
    if needs_root:
        cmd.insert(0, "sudo")

    # Ejecutar
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        meta = {
            "cmd": " ".join(shlex.quote(c) for c in cmd),
            "returncode": result.returncode,
            "stderr": result.stderr.strip()
        }
        return result.stdout, meta

    except subprocess.CalledProcessError as e:
        meta = {
            "cmd": " ".join(shlex.quote(c) for c in cmd),
            "returncode": e.returncode,
            "stderr": e.stderr.strip() if e.stderr else str(e)
        }
        return "", meta
