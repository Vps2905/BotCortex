import socket
import subprocess
import platform
from datetime import datetime


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5000: "Flask/App",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}


def get_local_subnet():
    """
    Attempts to detect local subnet.
    Default fallback is 192.168.1.0/24.
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        if local_ip.startswith("127."):
            return "192.168.1.0/24"

        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    except Exception:
        return "192.168.1.0/24"


def ping_host(ip):
    """
    Basic ping check.
    """
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(
            ["ping", param, "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_port(ip, port, timeout=0.5):
    """
    Checks if TCP port is open.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def calculate_device_risk(open_ports):
    """
    Risk score based on exposed services.
    """
    score = 0
    reasons = []

    risky_ports = {
        21: "FTP exposed",
        23: "Telnet exposed",
        445: "SMB exposed",
        3389: "RDP exposed",
        5900: "VNC exposed",
        6379: "Redis exposed"
    }

    for port in open_ports:
        if port in risky_ports:
            score += 25
            reasons.append(risky_ports[port])
        elif port in [22, 80, 443, 8080, 8443]:
            score += 10
            reasons.append(f"{COMMON_PORTS.get(port, 'Service')} exposed")
        else:
            score += 5
            reasons.append(f"Port {port} open")

    if score >= 60:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    return score, level, reasons


def scan_network(subnet_prefix="192.168.1", start=1, end=30):
    """
    Lightweight scanner for authorized local network only.
    Example subnet_prefix: 192.168.1
    Scans 192.168.1.1 to 192.168.1.30
    """
    results = []

    for host in range(start, end + 1):
        ip = f"{subnet_prefix}.{host}"

        alive = ping_host(ip)

        open_ports = []
        services = []

        if alive:
            for port, service in COMMON_PORTS.items():
                if scan_port(ip, port):
                    open_ports.append(port)
                    services.append(service)

            risk_score, risk_level, reasons = calculate_device_risk(open_ports)

            results.append({
                "ip": ip,
                "status": "Live",
                "open_ports": ", ".join(str(p) for p in open_ports) if open_ports else "None",
                "services": ", ".join(services) if services else "None",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "reasons": ", ".join(reasons) if reasons else "No exposed common services",
                "timestamp": datetime.utcnow()
            })

    return results
