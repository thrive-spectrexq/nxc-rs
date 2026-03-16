import paramiko
import logging
from netmiko import ConnectHandler
from napalm import get_network_driver

def ssh_command(host, command, username, password=None, key_filename=None):
    """Execute a command on a remote host via standard SSH (paramiko)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(host, username=username, password=password, key_filename=key_filename, timeout=10)
        stdin, stdout, stderr = client.exec_command(command)
        
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        client.close()
        
        return {
            "status": "success",
            "host": host,
            "stdout": output,
            "stderr": error
        }
    except Exception as e:
        return {
            "status": "error",
            "host": host,
            "message": str(e)
        }

def netmiko_command(host, command, username, password, device_type="cisco_ios"):
    """Execute a command via Netmiko (Vendor-specific CLI)."""
    try:
        device = {
            'device_type': device_type,
            'host': host,
            'username': username,
            'password': password,
        }
        with ConnectHandler(**device) as net_connect:
            output = net_connect.send_command(command)
        return {
            "status": "success",
            "host": host,
            "output": output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def napalm_get_facts(host, username, password, driver="ios"):
    """Standardized device inventory/facts via NAPALM."""
    try:
        driver_cls = get_network_driver(driver)
        device = driver_cls(host, username, password)
        device.open()
        facts = device.get_facts()
        device.close()
        return {
            "status": "success",
            "host": host,
            "facts": facts
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
