import socket

def dns_lookup(host, record_type="A"):
    """Perform a DNS lookup."""
    try:
        if record_type == "A":
            addr = socket.gethostbyname(host)
            return {
                "status": "success",
                "host": host,
                "type": "A",
                "result": addr
            }
        else:
            return {
                "status": "error",
                "message": f"Record type '{record_type}' not yet implemented in basic mockup"
            }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
