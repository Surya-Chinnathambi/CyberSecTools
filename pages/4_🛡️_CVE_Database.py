import streamlit as st
from cve_database import render_cve_database
from auth import check_authentication

# Page configuration
st.set_page_config(
    page_title="CVE Database - CyberSec Platform",
    page_icon="🛡️",
    layout="wide"
)

# Check authentication
if not check_authentication():
    st.stop()

# Render the CVE database interface
render_cve_database()
