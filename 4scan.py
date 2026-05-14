import socket
import sys
from datetime import datetime

BANNER = """
▄  ▗▖ ▗▄▄▖ ▗▄▄▖ ▗▄▖ ▗▖  ▗▖
█  ▐▌▐▌   ▐▌   ▐▌ ▐▌▐▛▚▖▐▌
▀▀▀▜▌ ▝▀▚▖▐▌   ▐▛▀▜▌▐▌ ▝▜▌
   ▐▌▗▄▄▞▘▝▚▄▄▖▐▌ ▐▌▐▌  ▐▌

  4SCAN — by ricoswabii
"""

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def run_scanner():
    print(BANNER)
    print("=" * 40)

    host = input("\nEnter target IP or website (e.g. 127.0.0.1): ")
    start_port = int(input("Start port (e.g. 1): "))
    end_port = int(input("End port (e.g. 100): "))

    print(f"\nScanning {host} from port {start_port} to {end_port}...")
    print(f"Started at: {datetime.now()}\n")

    open_ports = []

    for port in range(start_port, end_port + 1):
        if scan_port(host, port):
            print(f"  [OPEN]  Port {port}")
            open_ports.append(port)

    print(f"\nDone! {len(open_ports)} open port(s) found.")
    print(f"Finished at: {datetime.now()}")

run_scanner()