import subprocess
import re

def port_scan(host, ports="1-1024"):
    """Scan a host for open ports using nmap if available, otherwise fallback."""
    try:
        # Check if nmap is available
        command = ["nmap", "-p", ports, host]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        
        # Simple regex to extract open ports
        open_ports = re.findall(r"(\d+)/tcp\s+open", output)
        
        return {
            "status": "success",
            "host": host,
            "open_ports": open_ports,
            "raw_output": output
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "error": "nmap not found on system. Please install nmap for port scanning."
        }
    except subprocess.CalledProcessError as e:
        return {
            "status": "error",
            "host": host,
            "error": e.output
        }

def service_detect(host, ports):
    """Detect services on specific ports using nmap -sV."""
    try:
        command = ["nmap", "-sV", "-p", ports, host]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        return {
            "status": "success",
            "host": host,
            "raw_output": output
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}
