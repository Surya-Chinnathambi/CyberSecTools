import requests
import ssl
import socket
from urllib.parse import urljoin, urlparse
from datetime import datetime
import urllib3
from typing import Dict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VULN_PATHS = [
    '/admin', '/admin.php', '/administrator', '/phpmyadmin',
    '/wp-admin', '/wp-login.php', '/login', '/robots.txt',
    '/.htaccess', '/.env', '/config.php', '/backup',
    '/backup.sql', '/database.sql', '/.git', '/.svn',
    '/test', '/debug', '/info.php', '/phpinfo.php'
]

SECURITY_HEADERS = [
    'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection',
    'Strict-Transport-Security', 'Content-Security-Policy',
    'Referrer-Policy', 'Permissions-Policy'
]

def check_ssl_certificate(hostname: str, port: int = 443) -> Dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    'valid': True,
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter']
                }
    except Exception as e:
        return {'valid': False, 'error': str(e)}

def check_security_headers(url: str) -> Dict:
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers_found = {}
        missing_headers = []
        
        for header in SECURITY_HEADERS:
            if header in response.headers:
                headers_found[header] = response.headers[header]
            else:
                missing_headers.append(header)
        
        return {
            'status_code': response.status_code,
            'headers_found': headers_found,
            'missing_headers': missing_headers
        }
    except Exception as e:
        return {'error': str(e)}

def check_common_vulnerabilities(base_url: str) -> list:
    findings = []
    
    for path in VULN_PATHS:
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            
            if response.status_code == 200:
                risk = 'High' if any(x in path for x in ['.env', 'config', 'backup', '.git']) else 'Medium'
                findings.append({
                    'path': path,
                    'url': url,
                    'status_code': response.status_code,
                    'risk': risk
                })
        except:
            continue
    
    return findings

def perform_web_scan(url: str, options: Dict[str, bool]) -> Dict:
    results = {
        'url': url,
        'scan_time': datetime.now().isoformat(),
        'ssl_info': {},
        'security_headers': {},
        'vulnerability_paths': [],
        'risk_summary': {'high': 0, 'medium': 0, 'low': 0}
    }
    
    parsed_url = urlparse(url)
    
    if parsed_url.scheme == 'https' and options.get('scan_ssl', True):
        results['ssl_info'] = check_ssl_certificate(parsed_url.hostname)
    
    if options.get('scan_headers', True):
        results['security_headers'] = check_security_headers(url)
    
    if options.get('scan_paths', True):
        results['vulnerability_paths'] = check_common_vulnerabilities(url)
    
    if not results['ssl_info'].get('valid', True):
        results['risk_summary']['high'] += 1
    
    missing_count = len(results['security_headers'].get('missing_headers', []))
    if missing_count > 5:
        results['risk_summary']['high'] += 1
    elif missing_count > 2:
        results['risk_summary']['medium'] += 1
    
    for vuln in results['vulnerability_paths']:
        risk_level = vuln.get('risk', 'Low').lower()
        results['risk_summary'][risk_level] += 1
    
    return results
