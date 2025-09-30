import streamlit as st
from ai_chat import render_chat_interface
from auth import check_authentication

# Page configuration
st.set_page_config(
    page_title="AI Security Chat - CyberSec Platform",
    page_icon="🤖",
    layout="wide"
)

# Check authentication
if not check_authentication():
    st.stop()

# Render the AI chat interface
render_chat_interface()
