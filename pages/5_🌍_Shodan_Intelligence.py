import streamlit as st
from shodan_integration import render_shodan_intelligence
from auth import check_authentication

# Page configuration
st.set_page_config(
    page_title="Shodan Intelligence - CyberSec Platform",
    page_icon="🌍",
    layout="wide"
)

# Check authentication
if not check_authentication():
    st.stop()

# Render the Shodan intelligence interface
render_shodan_intelligence()
