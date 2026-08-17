#!/usr/bin/env python3

import argparse
import csv
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ============================================================
# 4SCAN — Simple Lightweight TCP Port Scanner
# by ric0swab11
# ============================================================

BANNER = r"""
▄  ▗▖ ▗▄▄▖ ▗▄▄▖ ▗▄▖ ▗▖  ▗▖
█  ▐▌▐▌   ▐▌   ▐▌ ▐▌▐▛▚▖▐▌
▀▀▀▜▌ ▝▀▚▖▐▌   ▐▛▀▜▌▐▌ ▝▜▌
   ▐▌▗▄▄▞▘▝▚▄▄▖▐▌ ▐▌▐▌  ▐▌

        4SCAN — by ricoswabii
        Lightweight TCP Scanner
"""

# ============================================================
# Colors
# ============================================================

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BOLD = "\033[1m"


# ============================================================
# Common services
# ============================================================

COMMON_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    2376: "Docker TLS",
    3000: "HTTP-Dev",
    3306: "MySQL",
    3389: "RDP",
    5000: "HTTP-Dev",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    6443: "Kubernetes",
    8000: "HTTP-Dev",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9000: "HTTP-Dev",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


# ============================================================
# Top common ports
# ============================================================

TOP_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69,
    80, 110, 111, 119, 123, 135, 137, 138,
    139, 143, 161, 389, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 2049, 2375,
    2376, 3000, 3306, 3389, 5000, 5432,
    5900, 6379, 6443, 8000, 8080, 8443,
    9000, 9200, 27017
]


# ============================================================
# Service detection
# ============================================================

def get_service(port):
    """
    Return a known service name for a port.
    Fall back to socket.getservbyport().
    """

    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"


# ============================================================
# Resolve target
# ============================================================

def resolve_target(target):
    """
    Resolve hostname/IP to an IPv4 address.
    """

    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"{RED}[ERROR]{RESET} Could not resolve target: {target}")
        sys.exit(1)


# ============================================================
# Parse ports
# ============================================================

def parse_ports(port_string):
    """
    Parse:

        80
        80,443,8080
        1-100
        22,80,443
        1-100,443,8080
    """

    ports = set()

    try:
        parts = port_string.split(",")

        for part in parts:
            part = part.strip()

            if "-" in part:
                start, end = part.split("-", 1)

                start = int(start)
                end = int(end)

                if start > end:
                    raise ValueError

                for port in range(start, end + 1):
                    if 1 <= port <= 65535:
                        ports.add(port)

            else:
                port = int(part)

                if 1 <= port <= 65535:
                    ports.add(port)

        if not ports:
            raise ValueError

        return sorted(ports)

    except ValueError:
        print(
            f"{RED}[ERROR]{RESET} Invalid port format.\n"
            f"Example: 80,443 or 1-1000"
        )
        sys.exit(1)


# ============================================================
# TCP Port Scan
# ============================================================

def scan_port(host, port, timeout):
    """
    Attempt a TCP connection to a port.
    """

    start_time = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex((host, port))

            elapsed = (time.perf_counter() - start_time) * 1000

            if result == 0:
                return {
                    "port": port,
                    "state": "open",
                    "service": get_service(port),
                    "response_ms": round(elapsed, 2)
                }

    except socket.timeout:
        pass

    except socket.error:
        pass

    elapsed = (time.perf_counter() - start_time) * 1000

    return {
        "port": port,
        "state": "closed",
        "service": get_service(port),
        "response_ms": round(elapsed, 2)
    }


# ============================================================
# Scan target
# ============================================================

def scan_target(host, ports, timeout, threads, verbose=False):

    results = []

    total = len(ports)
    completed = 0

    print()
    print(
        f"{CYAN}Scanning {host} "
        f"({total} ports){RESET}"
    )
    print()

    start_time = time.perf_counter()

    try:

        with ThreadPoolExecutor(max_workers=threads) as executor:

            futures = {
                executor.submit(
                    scan_port,
                    host,
                    port,
                    timeout
                ): port
                for port in ports
            }

            for future in as_completed(futures):

                result = future.result()

                completed += 1

                if result["state"] == "open":

                    results.append(result)

                    print(
                        f"{GREEN}[OPEN]{RESET} "
                        f"{result['port']:<6} "
                        f"{result['service']:<15} "
                        f"{result['response_ms']} ms"
                    )

                elif verbose:

                    print(
                        f"{GRAY}[CLOSED]{RESET} "
                        f"{result['port']}"
                    )

                progress = (
                    completed / total
                ) * 100

                print(
                    f"\r{GRAY}Progress: "
                    f"{completed}/{total} "
                    f"({progress:.1f}%){RESET}",
                    end="",
                    flush=True
                )

    except KeyboardInterrupt:

        print(
            f"\n\n{YELLOW}[!] Scan interrupted.{RESET}"
        )

        return results

    print()

    elapsed = time.perf_counter() - start_time

    results.sort(key=lambda x: x["port"])

    print()
    print("=" * 60)

    print(
        f"{GREEN}Scan completed.{RESET}"
    )

    print(
        f"Open ports : "
        f"{GREEN}{len(results)}{RESET}"
    )

    print(
        f"Duration   : "
        f"{elapsed:.2f} seconds"
    )

    return results


# ============================================================
# JSON export
# ============================================================

def save_json(filename, target, ip, results):

    data = {
        "scanner": "4SCAN",
        "author": "ricoswabii",
        "target": target,
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "open_ports": results
    }

    try:

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=4
            )

        print(
            f"{GREEN}[+] JSON saved:{RESET} {filename}"
        )

    except OSError as error:

        print(
            f"{RED}[ERROR]{RESET} "
            f"Could not save JSON: {error}"
        )


# ============================================================
# CSV export
# ============================================================

def save_csv(filename, results):

    try:

        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Port",
                "State",
                "Service",
                "Response Time (ms)"
            ])

            for result in results:

                writer.writerow([
                    result["port"],
                    result["state"],
                    result["service"],
                    result["response_ms"]
                ])

        print(
            f"{GREEN}[+] CSV saved:{RESET} {filename}"
        )

    except OSError as error:

        print(
            f"{RED}[ERROR]{RESET} "
            f"Could not save CSV: {error}"
        )


# ============================================================
# Display results
# ============================================================

def display_results(results):

    if not results:

        print(
            f"{YELLOW}No open ports found.{RESET}"
        )

        return

    print()
    print(
        f"{BOLD}{WHITE}"
        f"{'PORT':<10}"
        f"{'STATE':<12}"
        f"{'SERVICE':<18}"
        f"{'TIME':<12}"
        f"{RESET}"
    )

    print("-" * 52)

    for result in results:

        print(
            f"{result['port']:<10}"
            f"{GREEN}{result['state']:<12}{RESET}"
            f"{result['service']:<18}"
            f"{result['response_ms']} ms"
        )


# ============================================================
# Argument Parser
# ============================================================

def create_parser():

    parser = argparse.ArgumentParser(
        description=(
            "4SCAN — Lightweight TCP Port Scanner "
            "by ricoswabii"
        )
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "-p",
        "--ports",
        help=(
            "Ports to scan. "
            "Examples: 80,443 or 1-1000"
        )
    )

    parser.add_argument(
        "--top-ports",
        type=int,
        choices=[20, 50],
        help="Scan the most common ports"
    )

    parser.add_argument(
        "-T",
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1)"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="Number of concurrent workers (default: 100)"
    )

    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save results as JSON"
    )

    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Save results as CSV"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show closed ports"
    )

    return parser


# ============================================================
# Main
# ============================================================

def main():

    print(BANNER)

    parser = create_parser()

    args = parser.parse_args()

    # --------------------------------------------------------
    # Validate timeout
    # --------------------------------------------------------

    if args.timeout <= 0:
        print(
            f"{RED}[ERROR]{RESET} "
            f"Timeout must be greater than 0."
        )
        sys.exit(1)

    # --------------------------------------------------------
    # Validate workers
    # --------------------------------------------------------

    if args.workers < 1 or args.workers > 500:
        print(
            f"{RED}[ERROR]{RESET} "
            f"Workers must be between 1 and 500."
        )
        sys.exit(1)

    # --------------------------------------------------------
    # Resolve target
    # --------------------------------------------------------

    ip = resolve_target(args.target)

    print(
        f"{CYAN}Target :{RESET} {args.target}"
    )

    print(
        f"{CYAN}IP     :{RESET} {ip}"
    )

    # --------------------------------------------------------
    # Determine ports
    # --------------------------------------------------------

    if args.ports:

        ports = parse_ports(args.ports)

    elif args.top_ports:

        ports = TOP_PORTS[:args.top_ports]

    else:

        print(
            f"{RED}[ERROR]{RESET} "
            f"Specify --ports or --top-ports."
        )

        parser.print_help()

        sys.exit(1)

    print(
        f"{CYAN}Ports  :{RESET} "
        f"{ports[0]}-{ports[-1]}"
    )

    print(
        f"{CYAN}Timeout:{RESET} "
        f"{args.timeout}s"
    )

    print(
        f"{CYAN}Workers:{RESET} "
        f"{args.workers}"
    )

    print(
        f"{CYAN}Started:{RESET} "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    # --------------------------------------------------------
    # Scan
    # --------------------------------------------------------

    results = scan_target(
        ip,
        ports,
        args.timeout,
        args.workers,
        args.verbose
    )

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    display_results(results)

    # --------------------------------------------------------
    # Save files
    # --------------------------------------------------------

    if args.json:

        save_json(
            args.json,
            args.target,
            ip,
            results
        )

    if args.csv:

        save_csv(
            args.csv,
            results
        )

    print()

    print(
        f"{BLUE}4SCAN finished.{RESET}"
    )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:

        print(
            f"\n{YELLOW}[!] Exiting scan...{RESET}"
        )

        sys.exit(0)
