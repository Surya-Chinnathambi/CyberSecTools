import requests
import ssl
import socket
import streamlit as st
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse
import urllib3

# Suppress SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common vulnerability paths to check
VULN_PATHS = [
    '/admin',
    '/admin.php',
    '/administrator',
    '/phpmyadmin',
    '/wp-admin',
    '/wp-login.php',
    '/login',
    '/robots.txt',
    '/.htaccess',
    '/.env',
    '/config.php',
    '/backup',
    '/backup.sql',
    '/database.sql',
    '/.git',
    '/.svn',
    '/test',
    '/debug',
    '/info.php',
    '/phpinfo.php'
]

# Security headers to check
SECURITY_HEADERS = [
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'Referrer-Policy',
    'Permissions-Policy',
    'X-Permitted-Cross-Domain-Policies'
]

def check_ssl_certificate(hostname, port=443):
    """Check SSL certificate details"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                return {
                    'valid': True,
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': cert['version'],
                    'serial_number': cert['serialNumber'],
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter'],
                    'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown')
                }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }

def check_security_headers(url):
    """Check security headers"""
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
            'missing_headers': missing_headers,
            'all_headers': dict(response.headers)
        }
    except Exception as e:
        return {
            'error': str(e)
        }

def check_common_vulnerabilities(base_url):
    """Check for common vulnerability paths"""
    findings = []
    
    for path in VULN_PATHS:
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            
            if response.status_code == 200:
                findings.append({
                    'path': path,
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'content_type': response.headers.get('Content-Type', 'Unknown'),
                    'risk': classify_path_risk(path, response)
                })
            elif response.status_code in [301, 302, 307, 308]:
                findings.append({
                    'path': path,
                    'url': url,
                    'status_code': response.status_code,
                    'redirect_to': response.headers.get('Location', 'Unknown'),
                    'risk': 'Low'
                })
        except:
            continue
    
    return findings

def classify_path_risk(path, response):
    """Classify risk level of discovered paths"""
    high_risk_indicators = ['.env', 'config.php', 'backup', '.git', '.svn', 'database', 'phpinfo']
    medium_risk_indicators = ['admin', 'login', 'wp-admin', 'phpmyadmin']
    
    path_lower = path.lower()
    content = response.text.lower() if hasattr(response, 'text') else ''
    
    for indicator in high_risk_indicators:
        if indicator in path_lower or indicator in content:
            return 'High'
    
    for indicator in medium_risk_indicators:
        if indicator in path_lower:
            return 'Medium'
    
    return 'Low'

def check_http_methods(url):
    """Check supported HTTP methods"""
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH', 'TRACE']
    supported_methods = []
    
    for method in methods:
        try:
            response = requests.request(method, url, timeout=5, verify=False)
            if response.status_code not in [405, 501]:
                supported_methods.append({
                    'method': method,
                    'status_code': response.status_code,
                    'risk': 'High' if method in ['PUT', 'DELETE', 'TRACE'] else 'Low'
                })
        except:
            continue
    
    return supported_methods

def perform_web_scan(url, progress_callback=None):
    """Perform comprehensive web vulnerability scan"""
    results = {
        'url': url,
        'scan_time': datetime.now().isoformat(),
        'ssl_info': {},
        'security_headers': {},
        'vulnerability_paths': [],
        'http_methods': [],
        'server_info': {},
        'risk_summary': {
            'high': 0,
            'medium': 0,
            'low': 0
        }
    }
    
    total_checks = 5
    completed = 0
    
    def update_progress():
        nonlocal completed
        completed += 1
        if progress_callback:
            progress_callback(completed / total_checks)
    
    # Parse URL
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    
    # 1. SSL Certificate Check
    if parsed_url.scheme == 'https':
        results['ssl_info'] = check_ssl_certificate(hostname)
    update_progress()
    
    # 2. Security Headers Check
    results['security_headers'] = check_security_headers(url)
    update_progress()
    
    # 3. Common Vulnerability Paths
    results['vulnerability_paths'] = check_common_vulnerabilities(url)
    update_progress()
    
    # 4. HTTP Methods Check
    results['http_methods'] = check_http_methods(url)
    update_progress()
    
    # 5. Server Information
    try:
        response = requests.get(url, timeout=10, verify=False)
        results['server_info'] = {
            'server': response.headers.get('Server', 'Unknown'),
            'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
            'status_code': response.status_code,
            'content_type': response.headers.get('Content-Type', 'Unknown')
        }
    except Exception as e:
        results['server_info'] = {'error': str(e)}
    update_progress()
    
    # Calculate risk summary
    calculate_risk_summary(results)
    
    return results

def calculate_risk_summary(results):
    """Calculate overall risk summary"""
    risk_counts = {'high': 0, 'medium': 0, 'low': 0}
    
    # SSL risks
    if 'ssl_info' in results and not results['ssl_info'].get('valid', True):
        risk_counts['high'] += 1
    
    # Security headers risks
    if 'security_headers' in results:
        missing_count = len(results['security_headers'].get('missing_headers', []))
        if missing_count > 5:
            risk_counts['high'] += 1
        elif missing_count > 2:
            risk_counts['medium'] += 1
    
    # Vulnerability paths
    for vuln in results.get('vulnerability_paths', []):
        risk_level = vuln.get('risk', 'Low').lower()
        risk_counts[risk_level] += 1
    
    # HTTP methods
    for method in results.get('http_methods', []):
        risk_level = method.get('risk', 'Low').lower()
        risk_counts[risk_level] += 1
    
    results['risk_summary'] = risk_counts

def render_web_scanner():
    """Render web vulnerability scanner interface"""
    st.title("🌐 Web Vulnerability Scanner")
    st.markdown("**Comprehensive HTTP security analysis with SSL/TLS verification and vulnerability detection**")
    
    # Check authentication and limits
    from auth import check_scan_limit
    if not check_scan_limit():
        return
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # URL input
        url = st.text_input(
            "🎯 Target URL",
            placeholder="https://example.com",
            help="Enter a complete URL including http:// or https://"
        )
        
        # Scan options
        st.markdown("### 🔧 Scan Options")
        scan_ssl = st.checkbox("🔒 SSL/TLS Analysis", value=True)
        scan_headers = st.checkbox("🛡️ Security Headers", value=True)
        scan_paths = st.checkbox("🔍 Vulnerability Paths", value=True)
        scan_methods = st.checkbox("📡 HTTP Methods", value=True)
    
    with col2:
        st.markdown("### 🚀 Quick Targets")
        if st.button("🌐 Test HTTPS Site"):
            st.session_state.web_target = "https://www.google.com"
        if st.button("🔓 Test HTTP Site"):
            st.session_state.web_target = "http://neverssl.com"
        if st.button("🏠 Test Localhost"):
            st.session_state.web_target = "http://localhost:8080"
        
        # Apply quick target if selected
        if 'web_target' in st.session_state:
            url = st.session_state.web_target
            del st.session_state.web_target
    
    # Scan execution
    if st.button("🚀 Start Web Scan", type="primary", use_container_width=True):
        if not url:
            st.error("❌ Please enter a target URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            st.error("❌ URL must start with http:// or https://")
            return
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        results_container = st.empty()
        
        def update_progress(progress):
            progress_bar.progress(progress)
            status_text.text(f"🔍 Scanning... {progress*100:.1f}% complete")
        
        # Perform scan
        with st.spinner("🚀 Initializing web vulnerability scan..."):
            try:
                results = perform_web_scan(url, update_progress)
                
                # Save scan results
                user_info = st.session_state.get('user_info', {})
                if user_info:
                    from database import save_scan_result
                    save_scan_result(
                        user_info['id'],
                        'web_scan',
                        url,
                        json.dumps(results)
                    )
                
                # Display results
                status_text.text("✅ Scan completed!")
                display_web_scan_results(results, results_container)
                
            except Exception as e:
                st.error(f"❌ Scan failed: {str(e)}")

def display_web_scan_results(results, container):
    """Display web vulnerability scan results"""
    with container.container():
        st.markdown("## 📊 Web Vulnerability Scan Results")
        
        # Risk summary
        risk_summary = results.get('risk_summary', {})
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("🎯 Target", results['url'])
        
        with col2:
            st.metric("🔴 High Risk", risk_summary.get('high', 0))
        
        with col3:
            st.metric("🟡 Medium Risk", risk_summary.get('medium', 0))
        
        with col4:
            st.metric("🟢 Low Risk", risk_summary.get('low', 0))
        
        # SSL Information
        if 'ssl_info' in results and results['ssl_info']:
            st.markdown("### 🔒 SSL/TLS Certificate Analysis")
            ssl_info = results['ssl_info']
            
            if ssl_info.get('valid'):
                st.success("✅ Valid SSL Certificate")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Subject:**", ssl_info['subject'].get('commonName', 'N/A'))
                    st.write("**Issuer:**", ssl_info['issuer'].get('organizationName', 'N/A'))
                    st.write("**Valid From:**", ssl_info['not_before'])
                
                with col2:
                    st.write("**Valid Until:**", ssl_info['not_after'])
                    st.write("**Serial Number:**", ssl_info['serial_number'])
                    st.write("**Signature Algorithm:**", ssl_info['signature_algorithm'])
            else:
                st.error(f"❌ SSL Certificate Error: {ssl_info.get('error', 'Unknown error')}")
        
        # Security Headers
        if 'security_headers' in results:
            st.markdown("### 🛡️ Security Headers Analysis")
            headers_info = results['security_headers']
            
            if 'headers_found' in headers_info:
                found_headers = headers_info['headers_found']
                missing_headers = headers_info.get('missing_headers', [])
                
                if found_headers:
                    st.success(f"✅ Found {len(found_headers)} security headers")
                    for header, value in found_headers.items():
                        st.code(f"{header}: {value}")
                
                if missing_headers:
                    st.warning(f"⚠️ Missing {len(missing_headers)} security headers")
                    for header in missing_headers:
                        st.write(f"❌ {header}")
        
        # Vulnerability Paths
        if results.get('vulnerability_paths'):
            st.markdown("### 🔍 Discovered Paths")
            
            for vuln in results['vulnerability_paths']:
                risk_color = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}
                risk_emoji = risk_color.get(vuln['risk'], "🟢")
                
                with st.expander(f"{risk_emoji} {vuln['path']} - {vuln['risk']} Risk"):
                    st.write(f"**URL:** {vuln['url']}")
                    st.write(f"**Status Code:** {vuln['status_code']}")
                    if 'content_length' in vuln:
                        st.write(f"**Content Length:** {vuln['content_length']} bytes")
                    if 'redirect_to' in vuln:
                        st.write(f"**Redirects To:** {vuln['redirect_to']}")
        
        # HTTP Methods
        if results.get('http_methods'):
            st.markdown("### 📡 Supported HTTP Methods")
            
            for method_info in results['http_methods']:
                risk_color = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}
                risk_emoji = risk_color.get(method_info['risk'], "🟢")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write(f"{risk_emoji} **{method_info['method']}**")
                with col2:
                    st.write(f"Status: {method_info['status_code']}")
                with col3:
                    st.write(f"Risk: {method_info['risk']}")
        
        # Server Information
        if results.get('server_info'):
            st.markdown("### 🖥️ Server Information")
            server_info = results['server_info']
            
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Server:** {server_info.get('server', 'Unknown')}")
                st.write(f"**Powered By:** {server_info.get('powered_by', 'Unknown')}")
            
            with col2:
                st.write(f"**Status Code:** {server_info.get('status_code', 'Unknown')}")
                st.write(f"**Content Type:** {server_info.get('content_type', 'Unknown')}")
        
        # AI Analysis button
        if st.button("🤖 Get AI Security Analysis", key="web_ai_analysis"):
            with st.spinner("🧠 Analyzing web scan results..."):
                from ai_chat import analyze_scan_results
                analysis = analyze_scan_results("web vulnerability scan", results)
                st.markdown("### 🤖 AI Security Analysis")
                st.markdown(analysis)
