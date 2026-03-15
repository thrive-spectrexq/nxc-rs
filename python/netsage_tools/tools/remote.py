import paramiko
import logging

def ssh_command(host, command, username, password=None, key_filename=None):
    """Execute a command on a remote host via SSH."""
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

def netconf_get(host, username, password):
    """Placeholder for NETCONF get-config/get using ncclient."""
    return {
        "status": "error",
        "message": "NETCONF implementation requires ncclient which may have native dependencies. Mocking for now."
    }
