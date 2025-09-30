import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import List, Optional, Dict

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
    995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

def scan_port(host: str, port: int, timeout: int = 3) -> Dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    banner = ""
                return {
                    'port': port,
                    'status': 'open',
                    'service': COMMON_PORTS.get(port, 'Unknown'),
                    'banner': banner.strip()
                }
    except Exception:
        pass
    
    return {
        'port': port,
        'status': 'closed',
        'service': COMMON_PORTS.get(port, 'Unknown'),
        'banner': ''
    }

def perform_port_scan(host: str, ports: Optional[List[int]] = None, scan_type: str = "common") -> Dict:
    if ports is None:
        if scan_type == "common":
            ports = list(COMMON_PORTS.keys())
        elif scan_type == "top1000":
            ports = list(range(1, 1001))
        else:
            ports = list(COMMON_PORTS.keys())
    
    results = {
        'host': host,
        'scan_time': datetime.now().isoformat(),
        'open_ports': [],
        'closed_ports': [],
        'total_scanned': len(ports)
    }
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        scan_results = executor.map(lambda p: scan_port(host, p), ports)
    
    for result in scan_results:
        if result['status'] == 'open':
            results['open_ports'].append(result)
        else:
            results['closed_ports'].append(result)
    
    return results
