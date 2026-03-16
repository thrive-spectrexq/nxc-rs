from scapy.all import ARP, Ether, srp

def arp_scan(range_ip):
    """Perform an ARP scan on a network range."""
    try:
        # Create ARP request packet
        arp = ARP(pdst=range_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=2, verbose=0)[0]

        # Extract clients list
        clients = []
        for sent, received in result:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        return {
            "status": "success",
            "range": range_ip,
            "clients": clients,
            "count": len(clients)
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}
