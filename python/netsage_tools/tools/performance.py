import subprocess

def iperf_test(server, port=5201, duration=10):
    """Run an iperf3 bandwidth test (Mock/Wrapper)."""
    try:
        command = ["iperf3", "-c", server, "-p", str(port), "-t", str(duration), "--json"]
        output = subprocess.check_output(command, universal_newlines=True)
        return {
            "status": "success",
            "raw_json": output
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"iperf3 failed: {str(e)}"
        }
