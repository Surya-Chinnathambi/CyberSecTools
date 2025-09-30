import streamlit as st
import re
import ipaddress
from urllib.parse import urlparse
import json
from datetime import datetime, timedelta
import hashlib
import secrets
import base64

def validate_ip_address(ip):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def validate_domain(domain):
    """Validate domain name format"""
    pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    return pattern.match(domain) is not None

def validate_cve_id(cve_id):
    """Validate CVE ID format"""
    pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
    return pattern.match(cve_id) is not None

def sanitize_filename(filename):
    """Sanitize filename for safe file operations"""
    # Remove dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    # Limit length
    filename = filename[:255]
    return filename

def format_timestamp(timestamp):
    """Format timestamp for display"""
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            dt = timestamp
        
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Unknown"

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

def generate_session_id():
    """Generate secure session ID"""
    return secrets.token_urlsafe(32)

def hash_data(data):
    """Hash data using SHA-256"""
    return hashlib.sha256(str(data).encode()).hexdigest()

def encode_data(data):
    """Base64 encode data"""
    return base64.b64encode(json.dumps(data).encode()).decode()

def decode_data(encoded_data):
    """Base64 decode data"""
    try:
        return json.loads(base64.b64decode(encoded_data.encode()).decode())
    except:
        return None

def parse_port_range(port_range):
    """Parse port range string into list of ports"""
    ports = []
    
    try:
        if '-' in port_range:
            start, end = port_range.split('-')
            start, end = int(start), int(end)
            if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                ports = list(range(start, end + 1))
        elif ',' in port_range:
            port_list = port_range.split(',')
            for port in port_list:
                port = int(port.strip())
                if 1 <= port <= 65535:
                    ports.append(port)
        else:
            port = int(port_range)
            if 1 <= port <= 65535:
                ports = [port]
    except ValueError:
        pass
    
    return ports

def format_scan_duration(start_time, end_time=None):
    """Format scan duration"""
    try:
        if isinstance(start_time, str):
            start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        else:
            start = start_time
        
        if end_time:
            if isinstance(end_time, str):
                end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            else:
                end = end_time
        else:
            end = datetime.now()
        
        duration = end - start
        
        if duration.total_seconds() < 60:
            return f"{duration.total_seconds():.1f} seconds"
        elif duration.total_seconds() < 3600:
            return f"{duration.total_seconds() / 60:.1f} minutes"
        else:
            return f"{duration.total_seconds() / 3600:.1f} hours"
    except:
        return "Unknown"

def get_risk_color(risk_level):
    """Get color for risk level"""
    colors = {
        'critical': '#8B0000',
        'high': '#FF4B4B',
        'medium': '#FFA500',
        'low': '#32CD32',
        'info': '#4169E1',
        'none': '#808080'
    }
    return colors.get(risk_level.lower(), '#808080')

def get_risk_emoji(risk_level):
    """Get emoji for risk level"""
    emojis = {
        'critical': '🔴',
        'high': '🔴', 
        'medium': '🟡',
        'low': '🟢',
        'info': '🔵',
        'none': '⚪'
    }
    return emojis.get(risk_level.lower(), '⚪')

def truncate_text(text, max_length=100):
    """Truncate text to specified length"""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."

def display_success_message(message, duration=5):
    """Display success message with auto-dismiss"""
    success_container = st.success(message)
    if duration > 0:
        # In a real implementation, this would use JavaScript for auto-dismiss
        pass

def display_error_message(message, details=None):
    """Display error message with optional details"""
    st.error(message)
    if details:
        with st.expander("Error Details"):
            st.code(details)

def display_info_message(message, icon="ℹ️"):
    """Display info message with custom icon"""
    st.info(f"{icon} {message}")

def create_download_link(data, filename, link_text="Download"):
    """Create download link for data"""
    if isinstance(data, dict):
        data = json.dumps(data, indent=2)
    
    b64_data = base64.b64encode(data.encode()).decode()
    
    return f'<a href="data:text/plain;base64,{b64_data}" download="{filename}" style="text-decoration: none; color: #FF4B4B; font-weight: bold;">{link_text}</a>'

def parse_user_agent(user_agent):
    """Parse user agent string"""
    # Simple user agent parsing
    if 'Chrome' in user_agent:
        return {'browser': 'Chrome', 'type': 'Browser'}
    elif 'Firefox' in user_agent:
        return {'browser': 'Firefox', 'type': 'Browser'}
    elif 'curl' in user_agent.lower():
        return {'browser': 'curl', 'type': 'Tool'}
    elif 'nmap' in user_agent.lower():
        return {'browser': 'Nmap', 'type': 'Scanner'}
    else:
        return {'browser': 'Unknown', 'type': 'Unknown'}

def get_country_flag(country_code):
    """Get flag emoji for country code"""
    # Simplified country code to flag mapping
    flags = {
        'US': '🇺🇸', 'CN': '🇨🇳', 'RU': '🇷🇺', 'DE': '🇩🇪', 'GB': '🇬🇧',
        'FR': '🇫🇷', 'JP': '🇯🇵', 'KR': '🇰🇷', 'IN': '🇮🇳', 'BR': '🇧🇷',
        'CA': '🇨🇦', 'AU': '🇦🇺', 'IT': '🇮🇹', 'ES': '🇪🇸', 'NL': '🇳🇱'
    }
    return flags.get(country_code.upper(), '🏳️')

def format_cvss_score(score):
    """Format CVSS score with color and description"""
    if score >= 9.0:
        return f"🔴 {score}/10 (Critical)"
    elif score >= 7.0:
        return f"🟠 {score}/10 (High)"
    elif score >= 4.0:
        return f"🟡 {score}/10 (Medium)"
    elif score >= 0.1:
        return f"🟢 {score}/10 (Low)"
    else:
        return f"⚪ {score}/10 (None)"

def check_rate_limit(user_id, action, limit=10, window=3600):
    """Simple rate limiting check"""
    # In a real implementation, this would use Redis or database
    # For now, just return True (no rate limiting)
    return True

def log_security_event(user_id, event_type, details):
    """Log security events"""
    # In a real implementation, this would log to security monitoring system
    timestamp = datetime.now().isoformat()
    event = {
        'timestamp': timestamp,
        'user_id': user_id,
        'event_type': event_type,
        'details': details
    }
    
    # For demo, we'll just print to console
    print(f"Security Event: {json.dumps(event)}")

def mask_sensitive_data(data, fields=['password', 'api_key', 'token']):
    """Mask sensitive fields in data"""
    if isinstance(data, dict):
        masked_data = data.copy()
        for field in fields:
            if field in masked_data:
                masked_data[field] = '*' * 8
        return masked_data
    return data

def generate_report_id():
    """Generate unique report ID"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    random_suffix = secrets.token_hex(4)
    return f"RPT_{timestamp}_{random_suffix}"

def validate_scan_target(target, scan_type):
    """Validate scan target based on scan type"""
    if scan_type in ['port_scan', 'network_scan']:
        return validate_ip_address(target) or validate_domain(target)
    elif scan_type in ['web_scan', 'ssl_scan']:
        return validate_url(target)
    elif scan_type == 'cve_search':
        return validate_cve_id(target) or len(target.strip()) > 2
    else:
        return len(target.strip()) > 0

def get_scan_type_icon(scan_type):
    """Get icon for scan type"""
    icons = {
        'port_scan': '🔍',
        'web_scan': '🌐',
        'ssl_scan': '🔒',
        'cve_search': '🛡️',
        'shodan_search': '🌍',
        'exploit_search': '💥'
    }
    return icons.get(scan_type, '📊')

def calculate_security_score(scan_results):
    """Calculate overall security score from scan results"""
    total_score = 100
    
    for scan_type, results in scan_results.items():
        if scan_type == 'port_scan':
            open_ports = len(results.get('open_ports', []))
            if open_ports > 20:
                total_score -= 30
            elif open_ports > 10:
                total_score -= 20
            elif open_ports > 5:
                total_score -= 10
                
        elif scan_type == 'web_scan':
            risk_summary = results.get('risk_summary', {})
            total_score -= risk_summary.get('high', 0) * 15
            total_score -= risk_summary.get('medium', 0) * 8
            total_score -= risk_summary.get('low', 0) * 3
    
    return max(0, min(100, total_score))

def export_scan_results(scan_results, format='json'):
    """Export scan results in specified format"""
    if format == 'json':
        return json.dumps(scan_results, indent=2)
    elif format == 'csv':
        # Simple CSV export (would need proper CSV library for complex data)
        return "CSV export not implemented in demo"
    else:
        return str(scan_results)

def get_time_ago(timestamp):
    """Get human-readable time ago string"""
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            dt = timestamp
        
        now = datetime.now()
        diff = now - dt.replace(tzinfo=None)
        
        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"
    except:
        return "Unknown time"
