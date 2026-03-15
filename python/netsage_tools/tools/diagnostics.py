import subprocess
import platform

def ping_host(host, count=4):
    """Send ICMP echo requests to a host."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, str(count), host]
    
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        return {
            "status": "success",
            "host": host,
            "raw_output": output
        }
    except subprocess.CalledProcessError as e:
        return {
            "status": "error",
            "host": host,
            "error": e.output
        }
