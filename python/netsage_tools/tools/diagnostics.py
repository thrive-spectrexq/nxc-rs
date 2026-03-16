import subprocess
import platform

from scapy.all import IP, ICMP, sr1, traceroute as scapy_traceroute
import time

def ping_host(host, count=4):
    """Send ICMP echo requests to a host using scapy."""
    results = []
    for _ in range(count):
        packet = IP(dst=host)/ICMP()
        start_time = time.time()
        reply = sr1(packet, timeout=2, verbose=0)
        end_time = time.time()
        
        if reply:
            results.append({
                "rtt": (end_time - start_time) * 1000,
                "ttl": reply.ttl,
                "size": len(reply)
            })
        else:
            results.append(None)
            
    successes = [r for r in results if r]
    if not successes:
        return {
            "status": "error",
            "host": host,
            "error": "No response from host"
        }
        
    return {
        "status": "success",
        "host": host,
        "sent": count,
        "received": len(successes),
        "rtt_min": min(r["rtt"] for r in successes),
        "rtt_avg": sum(r["rtt"] for r in successes) / len(successes),
        "rtt_max": max(r["rtt"] for r in successes),
    }

def traceroute(host, max_hops=30):
    """Perform a traceroute to a host using scapy."""
    try:
        res, unans = scapy_traceroute(host, maxttl=max_hops, verbose=0)
        hops = []
        for snd, rcv in res:
            hops.append({
                "hop": snd.ttl,
                "ip": rcv.src,
                "rtt": (rcv.time - snd.sent_time) * 1000
            })
            
        return {
            "status": "success",
            "host": host,
            "hops": hops
        }
    except Exception as e:
        return {
            "status": "error",
            "host": host,
            "error": str(e)
        }

