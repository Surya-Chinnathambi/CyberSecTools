import streamlit as st
from billing import render_billing_interface
from auth import check_authentication

# Page configuration
st.set_page_config(
    page_title="Billing - CyberSec Platform",
    page_icon="💳",
    layout="wide"
)

# Check authentication
if not check_authentication():
    st.stop()

# Render the billing interface
render_billing_interface()
