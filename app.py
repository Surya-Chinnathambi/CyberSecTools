import streamlit as st
import sqlite3
from auth import init_auth, check_authentication
from database import init_database
from dashboard import render_dashboard
import os

# Page configuration
st.set_page_config(
    page_title="CyberSec AI Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize database and authentication
init_database()
init_auth()

# Custom CSS for animations and styling
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(45deg, #FF4B4B, #FF6B6B);
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
    }
    
    .threat-alert {
        background: linear-gradient(45deg, #FF4B4B, #FF0000);
        padding: 1rem;
        border-radius: 10px;
        animation: blink 1s infinite;
    }
    
    @keyframes blink {
        0%, 50% { opacity: 1; }
        51%, 100% { opacity: 0.7; }
    }
    
    .scan-progress {
        background: linear-gradient(90deg, #00FF00, #32CD32);
        height: 20px;
        border-radius: 10px;
        animation: progress 3s ease-in-out infinite;
    }
    
    @keyframes progress {
        0% { width: 0%; }
        100% { width: 100%; }
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Check authentication
    if not check_authentication():
        st.title("🛡️ CyberSec AI Platform")
        st.error("Please log in to access the platform")
        return
    
    # Sidebar navigation
    with st.sidebar:
        st.title("🛡️ CyberSec AI")
        st.markdown("---")
        
        # User info
        user_info = st.session_state.get('user_info', {})
        st.write(f"👤 **{user_info.get('username', 'Unknown User')}**")
        st.write(f"🎖️ **{user_info.get('role', 'free').title()} Tier**")
        
        # Usage tracking
        usage = st.session_state.get('usage', {'scans': 0, 'limit': 5 if user_info.get('role') == 'free' else 999})
        progress = min(usage['scans'] / usage['limit'], 1.0)
        st.progress(progress)
        st.caption(f"Scans used: {usage['scans']}/{usage['limit']}")
        
        st.markdown("---")
        
        # Navigation
        st.markdown("### 🧭 Navigation")
        st.markdown("Use the pages in the sidebar to access different tools:")
        st.markdown("- 🤖 AI Security Chat")
        st.markdown("- 🔍 Network Scanner")
        st.markdown("- 🌐 Web Vulnerability Scanner")
        st.markdown("- 🛡️ CVE Database")
        st.markdown("- 🌍 Shodan Intelligence")
        st.markdown("- 💥 Exploit Database")
        st.markdown("- 📊 Reports")
        st.markdown("- 💳 Billing")
        
        st.markdown("---")
        
        if st.button("🚪 Logout"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    # Main dashboard
    render_dashboard()

if __name__ == "__main__":
    main()
