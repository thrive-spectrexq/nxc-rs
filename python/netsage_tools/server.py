import sys
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ToolEngine:
    def __init__(self):
        self.tools = {}

    def register_tool(self, name, func):
        self.tools[name] = func

    def handle_request(self, request_line):
        try:
            request = json.loads(request_line)
            if request.get("method") != "execute_tool":
                return self.error_response(request.get("id"), -32601, "Method not found")
            
            params = request.get("params", {})
            tool_name = params.get("tool")
            args = params.get("args", {})

            if tool_name not in self.tools:
                return self.error_response(request.get("id"), -32602, f"Tool '{tool_name}' not found")

            result = self.tools[tool_name](**args)
            return self.success_response(request.get("id"), result)

        except Exception as e:
            return self.error_response(None, -32603, str(e))

    def success_response(self, id, result):
        return json.dumps({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        })

    def error_response(self, id, code, message):
        return json.dumps({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": code, "message": message}
        })

    def run(self):
        logging.info("Python Tool Engine started")
        for line in sys.stdin:
            if not line.strip():
                continue
            response = self.handle_request(line)
            sys.stdout.write(response + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    engine = ToolEngine()
    
    # Phase 1 & 2
    from netsage_tools.tools.diagnostics import ping_host, traceroute
    from netsage_tools.tools.dns import dns_lookup
    from netsage_tools.tools.discovery import port_scan, service_detect
    from netsage_tools.tools.lan import arp_scan
    
    # Phase 3
    from netsage_tools.tools.remote import ssh_command, netconf_get
    from netsage_tools.tools.intelligence import geoip_lookup, asn_lookup, whois_lookup
    from netsage_tools.tools.performance import iperf_test
    
    engine.register_tool("ping_host", ping_host)
    engine.register_tool("traceroute", traceroute)
    engine.register_tool("dns_lookup", dns_lookup)
    engine.register_tool("port_scan", port_scan)
    engine.register_tool("service_detect", service_detect)
    engine.register_tool("arp_scan", arp_scan)

    engine.register_tool("ssh_command", ssh_command)
    engine.register_tool("netconf_get", netconf_get)
    engine.register_tool("geoip_lookup", geoip_lookup)
    engine.register_tool("asn_lookup", asn_lookup)
    engine.register_tool("whois_lookup", whois_lookup)
    engine.register_tool("iperf_test", iperf_test)
    
    engine.run()
