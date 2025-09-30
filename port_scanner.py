import socket
import threading
import time
import streamlit as st
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Common ports to scan
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

def scan_port(host, port, timeout=3):
    """Scan a single port"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    # Try to grab banner
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

def validate_target(target):
    """Validate scan target"""
    try:
        socket.gethostbyname(target)
        return True, ""
    except socket.gaierror:
        return False, "Invalid hostname or IP address"

def perform_port_scan(host, ports, progress_callback=None):
    """Perform port scan with progress tracking"""
    results = {
        'host': host,
        'scan_time': datetime.now().isoformat(),
        'open_ports': [],
        'closed_ports': [],
        'total_scanned': len(ports)
    }
    
    completed = 0
    
    def scan_with_progress(port):
        nonlocal completed
        result = scan_port(host, port)
        
        if result['status'] == 'open':
            results['open_ports'].append(result)
        else:
            results['closed_ports'].append(result)
        
        completed += 1
        if progress_callback:
            progress_callback(completed / len(ports))
        
        return result
    
    # Use ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan_with_progress, ports)
    
    return results

def render_port_scanner():
    """Render port scanner interface"""
    st.title("🔍 Network Port Scanner")
    st.markdown("**Real-time network port scanning with live progress tracking**")
    
    # Check authentication and limits
    from auth import check_scan_limit
    if not check_scan_limit():
        return
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Target input
        target = st.text_input(
            "🎯 Target Host/IP",
            placeholder="example.com or 192.168.1.1",
            help="Enter a hostname or IP address to scan"
        )
        
        # Port selection
        scan_type = st.selectbox(
            "📡 Scan Type",
            ["Common Ports (Fast)", "Top 1000 Ports", "Custom Range", "Full Scan (1-65535)"]
        )
        
        if scan_type == "Custom Range":
            col_start, col_end = st.columns(2)
            with col_start:
                start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=1)
            with col_end:
                end_port = st.number_input("End Port", min_value=1, max_value=65535, value=1000)
            ports = list(range(start_port, end_port + 1))
        elif scan_type == "Common Ports (Fast)":
            ports = list(COMMON_PORTS.keys())
        elif scan_type == "Top 1000 Ports":
            # Top 1000 most common ports
            ports = list(range(1, 1001))
        else:  # Full Scan
            ports = list(range(1, 65536))
        
        st.info(f"📊 **Ports to scan:** {len(ports)}")
    
    with col2:
        st.markdown("### 🚀 Quick Targets")
        if st.button("🌐 Scan Google DNS"):
            st.session_state.scan_target = "8.8.8.8"
        if st.button("🏠 Scan Localhost"):
            st.session_state.scan_target = "127.0.0.1"
        if st.button("🔍 Scan Router"):
            st.session_state.scan_target = "192.168.1.1"
        
        # Apply quick target if selected
        if 'scan_target' in st.session_state:
            target = st.session_state.scan_target
            del st.session_state.scan_target
    
    # Scan execution
    if st.button("🚀 Start Port Scan", type="primary", use_container_width=True):
        if not target:
            st.error("❌ Please enter a target host or IP address")
            return
        
        # Validate target
        valid, error_msg = validate_target(target)
        if not valid:
            st.error(f"❌ {error_msg}")
            return
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        results_container = st.empty()
        
        def update_progress(progress):
            progress_bar.progress(progress)
            status_text.text(f"🔍 Scanning... {progress*100:.1f}% complete")
        
        # Perform scan
        with st.spinner("🚀 Initializing port scan..."):
            try:
                results = perform_port_scan(target, ports, update_progress)
                
                # Save scan results
                user_info = st.session_state.get('user_info', {})
                if user_info:
                    from database import save_scan_result
                    save_scan_result(
                        user_info['id'],
                        'port_scan',
                        target,
                        json.dumps(results)
                    )
                
                # Display results
                status_text.text("✅ Scan completed!")
                display_scan_results(results, results_container)
                
            except Exception as e:
                st.error(f"❌ Scan failed: {str(e)}")

def display_scan_results(results, container):
    """Display port scan results"""
    with container.container():
        st.markdown("## 📊 Scan Results")
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "🎯 Target",
                results['host']
            )
        
        with col2:
            st.metric(
                "🔓 Open Ports",
                len(results['open_ports'])
            )
        
        with col3:
            st.metric(
                "🔒 Closed Ports", 
                len(results['closed_ports'])
            )
        
        with col4:
            st.metric(
                "📊 Total Scanned",
                results['total_scanned']
            )
        
        # Open ports details
        if results['open_ports']:
            st.markdown("### 🔓 Open Ports")
            
            for port_info in results['open_ports']:
                with st.expander(f"Port {port_info['port']} - {port_info['service']}", expanded=True):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Port:** {port_info['port']}")
                        st.write(f"**Service:** {port_info['service']}")
                        st.write(f"**Status:** 🔓 {port_info['status'].title()}")
                    
                    with col2:
                        if port_info['banner']:
                            st.write("**Banner:**")
                            st.code(port_info['banner'][:200] + "..." if len(port_info['banner']) > 200 else port_info['banner'])
                        else:
                            st.write("**Banner:** None detected")
                    
                    # Security analysis
                    analyze_port_security(port_info)
        else:
            st.warning("🔒 No open ports found. The target may be behind a firewall or not responding.")
        
        # AI Analysis button
        if st.button("🤖 Get AI Security Analysis", key="ai_analysis"):
            with st.spinner("🧠 Analyzing scan results..."):
                from ai_chat import analyze_scan_results
                analysis = analyze_scan_results("port scan", results)
                st.markdown("### 🤖 AI Security Analysis")
                st.markdown(analysis)

def analyze_port_security(port_info):
    """Analyze security implications of open ports"""
    port = port_info['port']
    service = port_info['service']
    
    # Security recommendations based on port
    security_info = {
        21: {"risk": "🔴 High", "note": "FTP - Often insecure, consider SFTP"},
        22: {"risk": "🟡 Medium", "note": "SSH - Secure if properly configured"},
        23: {"risk": "🔴 High", "note": "Telnet - Unencrypted, use SSH instead"},
        25: {"risk": "🟡 Medium", "note": "SMTP - Monitor for spam/abuse"},
        53: {"risk": "🟢 Low", "note": "DNS - Normal service"},
        80: {"risk": "🟡 Medium", "note": "HTTP - Consider HTTPS upgrade"},
        443: {"risk": "🟢 Low", "note": "HTTPS - Secure web service"},
        3389: {"risk": "🔴 High", "note": "RDP - High-value target, restrict access"},
        3306: {"risk": "🔴 High", "note": "MySQL - Database should not be public"},
        5432: {"risk": "🔴 High", "note": "PostgreSQL - Database should not be public"},
        6379: {"risk": "🔴 High", "note": "Redis - Should not be publicly accessible"}
    }
    
    info = security_info.get(port, {"risk": "🟡 Medium", "note": "Review if this service should be public"})
    
    st.markdown(f"**Security Risk:** {info['risk']}")
    st.markdown(f"**Recommendation:** {info['note']}")
