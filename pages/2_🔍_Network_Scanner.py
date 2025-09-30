import streamlit as st
from port_scanner import render_port_scanner
from auth import check_authentication

# Page configuration
st.set_page_config(
    page_title="Network Scanner - CyberSec Platform", 
    page_icon="🔍",
    layout="wide"
)

# Check authentication
if not check_authentication():
    st.stop()

# Render the port scanner interface
render_port_scanner()
