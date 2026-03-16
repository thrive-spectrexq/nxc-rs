import socket
import logging
import requests

def geoip_lookup(ip):
    """Perform a GeoIP lookup using ip-api.com."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data.get("status") == "success":
            return {
                "status": "success",
                "ip": ip,
                "country": data.get("country"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as")
            }
        else:
            return {"status": "error", "message": data.get("message", "Unknown error")}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def asn_lookup(ip):
    """Perform an ASN lookup via the same GeoIP API."""
    res = geoip_lookup(ip)
    if res["status"] == "success":
        return {
            "status": "success",
            "ip": ip,
            "asn": res.get("asn"),
            "org": res.get("org")
        }
    return res

def whois_lookup(domain):
    """Perform a WHOIS lookup."""
    try:
        import whois
        w = whois.whois(domain)
        return {
            "status": "success",
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "org": w.org
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"WHOIS failed: {str(e)}"
        }
