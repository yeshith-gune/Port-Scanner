# scanner.py
import socket
import ipaddress
import concurrent.futures
import time
import sys
import os
from datetime import datetime
from services import get_service


# ── Section 1: Validate Target ───────────────────────────────────────────────

def resolve_target(target):
    """
    Accept either a hostname (google.com) or IP address.
    Returns the resolved IP address as a string.
    """
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"\n  Error: Could not resolve '{target}'")
        print("  Check the hostname or IP address and try again.\n")
        sys.exit(1)


def validate_ip(ip):
    """Validate that a string is a proper IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ── Section 2: Scan a Single Port ────────────────────────────────────────────

def scan_port(ip, port, timeout=1.0):
    """
    Try to connect to a single port on the target IP.
    Returns a dict with the result.
    """
    result = {
        'port':     port,
        'state':    'closed',
        'service':  get_service(port),
        'banner':   '',
        'response': 0.0
    }

    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Record time before connection attempt
        start = time.time()

        # Try to connect — this is the actual port knock
        connection = sock.connect_ex((ip, port))

        # Record response time
        result['response'] = round((time.time() - start) * 1000, 2)  # ms

        if connection == 0:
            # Port is open — try to grab a banner
            result['state'] = 'open'
            try:
                sock.settimeout(2.0)
                # Send a basic HTTP request for web ports
                if port in [80, 8080, 8888]:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                else:
                    sock.send(b'\r\n')
                banner = sock.recv(1024).decode(
                    'utf-8', errors='ignore').strip()
                # Clean up banner — take first line only
                result['banner'] = banner.split('\n')[0][:60] if banner else ''
            except:
                pass  # banner grab failed — that's fine

        sock.close()

    except socket.error:
        pass  # connection failed — port is closed

    return result


# ── Section 3: Scan Multiple Ports (with threading) ──────────────────────────

def scan_ports(ip, ports, timeout=1.0, threads=100):
    """
    Scan a list of ports using multiple threads for speed.
    Returns list of open port results.
    """
    open_ports = []
    total = len(ports)
    scanned = 0

    print(f"\n  Scanning {total} ports on {ip}...")
    print(f"  Using {threads} threads | Timeout: {timeout}s\n")

    # ThreadPoolExecutor runs many scans at the same time
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all port scans at once
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }

        # Collect results as they finish
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            scanned += 1

            # Draw a live progress bar
            percent = int((scanned / total) * 40)
            bar = "█" * percent + "░" * (40 - percent)
            print(f"\r  [{bar}] {scanned}/{total} ports", end='', flush=True)

            # Only keep open ports
            if result['state'] == 'open':
                open_ports.append(result)

    print()  # new line after progress bar

    # Sort open ports by port number
    open_ports.sort(key=lambda x: x['port'])
    return open_ports


# ── Section 4: Parse Port Range Input ────────────────────────────────────────

def parse_ports(port_input):
    """
    Parse user port input into a list of integers.
    Supports:
      - Single port:  "80"
      - Range:        "1-1024"
      - List:         "22,80,443"
      - Common:       "common"
      - All:          "all"
    """
    COMMON_PORTS = [
        20, 21, 22, 23, 25, 53, 67, 68, 80, 110,
        119, 123, 135, 139, 143, 161, 194, 389, 443, 445,
        465, 514, 587, 631, 993, 995, 1080, 1194, 1433, 1521,
        2082, 2083, 2222, 3306, 3389, 4444, 5432, 5900, 6379,
        8080, 8443, 8888, 9200, 27017
    ]

    port_input = port_input.strip().lower()

    if port_input == 'common':
        return COMMON_PORTS

    if port_input == 'all':
        return list(range(1, 65536))

    if '-' in port_input:
        start, end = port_input.split('-')
        return list(range(int(start), int(end) + 1))

    if ',' in port_input:
        return [int(p.strip()) for p in port_input.split(',')]

    # Single port
    return [int(port_input)]


# ── Section 5: Print Results Table ───────────────────────────────────────────

def print_results(target, ip, open_ports, scan_time, ports_scanned):
    """Print a clean formatted results table."""

    print("\n" + "=" * 65)
    print("  PORT SCAN RESULTS")
    print("=" * 65)
    print(f"  Target     : {target}")
    print(f"  IP Address : {ip}")
    print(f"  Scan time  : {scan_time:.2f} seconds")
    print(f"  Ports      : {ports_scanned} scanned")
    print(f"  Open ports : {len(open_ports)} found")
    print(f"  Scanned at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    if not open_ports:
        print("\n  No open ports found.\n")
        return

    # Table header
    print(f"\n  {'PORT':<8} {'STATE':<10} {'SERVICE':<28} {'RESPONSE':<12} BANNER")
    print(f"  {'─'*6:<8} {'─'*8:<10} {'─'*26:<28} {'─'*10:<12} {'─'*20}")

    for p in open_ports:
        banner = p['banner'][:30] + \
            "..." if len(p['banner']) > 30 else p['banner']
        print(f"  {str(p['port'])+'/'+'tcp':<8} "
              f"{'open':<10} "
              f"{p['service']:<28} "
              f"{str(p['response'])+'ms':<12} "
              f"{banner}")

    print()

    # Security observations
    risky = {
        23:   "Telnet is unencrypted — should be disabled",
        21:   "FTP transfers data in plaintext — use SFTP instead",
        80:   "HTTP is unencrypted — consider HTTPS only",
        3389: "RDP exposed — high risk for brute force attacks",
        4444: "Port 4444 is Metasploit default — investigate immediately",
        445:  "SMB exposed — check for EternalBlue vulnerability",
        1433: "MSSQL exposed to network — restrict with firewall",
        3306: "MySQL exposed to network — restrict with firewall",
    }

    warnings = [
        f"  ⚠  Port {p['port']}: {risky[p['port']]}"
        for p in open_ports if p['port'] in risky
    ]

    if warnings:
        print("─" * 65)
        print("  SECURITY OBSERVATIONS")
        print("─" * 65)
        for w in warnings:
            print(w)
        print()


# ── Section 6: Save Report to File ───────────────────────────────────────────

def save_report(target, ip, open_ports, scan_time, ports_scanned):
    """Save scan results to a text file."""
    filename = f"scan_{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, 'w') as f:
        f.write("PORT SCAN REPORT\n")
        f.write("=" * 65 + "\n")
        f.write(f"Target     : {target}\n")
        f.write(f"IP Address : {ip}\n")
        f.write(
            f"Scanned at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scan time  : {scan_time:.2f} seconds\n")
        f.write(f"Ports      : {ports_scanned} scanned\n")
        f.write(f"Open ports : {len(open_ports)}\n")
        f.write("=" * 65 + "\n\n")

        if open_ports:
            f.write(f"{'PORT':<10} {'SERVICE':<28} {'RESPONSE':<12} BANNER\n")
            f.write("-" * 65 + "\n")
            for p in open_ports:
                f.write(f"{str(p['port'])+'/'+'tcp':<10} "
                        f"{p['service']:<28} "
                        f"{str(p['response'])+'ms':<12} "
                        f"{p['banner']}\n")
        else:
            f.write("No open ports found.\n")

    print(f"  Report saved to: {filename}\n")
    return filename


# ── Section 7: Main Program ───────────────────────────────────────────────────

def main():
    print("\n" + "=" * 65)
    print("  PYTHON PORT SCANNER")
    print("  Built from scratch using sockets")
    print("=" * 65)
    print("\n  Only scan systems you own or have permission to scan.")
    print("  Scanning without permission is illegal.\n")

    # Get target
    target = input("  Enter target IP or hostname: ").strip()
    if not target:
        print("  No target entered.")
        sys.exit(1)

    # Resolve to IP
    ip = resolve_target(target)
    if target != ip:
        print(f"  Resolved: {target} → {ip}")

    # Get port range
    print("\n  Port options:")
    print("  common  → top 44 most important ports (fast)")
    print("  1-1024  → well-known ports")
    print("  all     → all 65535 ports (slow ~10 mins)")
    print("  80,443,22 → specific ports")
    port_input = input(
        "\n  Enter ports to scan [default: common]: ").strip() or "common"
    ports = parse_ports(port_input)

    # Get timeout
    timeout_input = input(
        "  Timeout per port in seconds [default: 1.0]: ").strip()
    timeout = float(timeout_input) if timeout_input else 1.0

    # Run the scan
    start_time = time.time()
    open_ports = scan_ports(ip, ports, timeout=timeout, threads=100)
    scan_time = time.time() - start_time

    # Print results
    print_results(target, ip, open_ports, scan_time, len(ports))

    # Save report
    save = input("  Save report to file? (y/n): ").strip().lower()
    if save == 'y':
        save_report(target, ip, open_ports, scan_time, len(ports))

    # Compare with Nmap
    print("  Tip: Verify your results with Nmap:")
    print(f"  nmap -sV {ip}\n")


if __name__ == "__main__":
    main()
