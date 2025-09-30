import streamlit as st
import os
import json
from openai import OpenAI

# Using GPT-4o for advanced cybersecurity analysis and recommendations
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODELS = ["gpt-4o-mini", "gpt-4o", "gpt-4"]  # Fallback model priority

# Initialize OpenAI client if API key is available
openai = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

SECURITY_SYSTEM_PROMPT = """
You are an expert cybersecurity AI assistant specializing in:
- Network security analysis and threat assessment
- Vulnerability identification and remediation
- Penetration testing methodologies and best practices
- CVE analysis and risk evaluation
- Security compliance frameworks (OWASP, PCI-DSS, HIPAA)
- Incident response and forensics
- Security architecture and defense strategies

Provide detailed, actionable security advice. When discussing vulnerabilities:
1. Explain the technical details clearly
2. Assess the risk level and potential impact
3. Provide specific remediation steps
4. Reference relevant compliance frameworks
5. Suggest additional security measures

Always prioritize ethical security practices and responsible disclosure.
"""

def initialize_chat():
    """Initialize chat session"""
    if 'chat_messages' not in st.session_state:
        st.session_state.chat_messages = [
            {
                "role": "assistant",
                "content": "🛡️ **CyberSec AI Assistant Ready**\n\nI'm your specialized cybersecurity AI assistant. I can help you with:\n\n- 🔍 **Security Analysis** - Analyze vulnerabilities and threats\n- 🛠️ **Remediation Guidance** - Step-by-step fix recommendations\n- 📋 **Compliance Mapping** - OWASP, PCI-DSS, HIPAA alignment\n- 🎯 **Penetration Testing** - Methodology and best practices\n- 🚨 **Incident Response** - Threat analysis and containment\n\nWhat security challenge can I help you tackle today?"
            }
        ]

def get_ai_response(user_message, context=None):
    """Get AI response for security queries"""
    if not openai or not OPENAI_API_KEY:
        return "❌ **OpenAI API Key Required**: Please configure your OPENAI_API_KEY to use AI features."
    
    try:
        messages = [{"role": "system", "content": SECURITY_SYSTEM_PROMPT}]
        
        # Add context if provided (e.g., scan results)
        if context:
            context_message = f"Additional context for analysis:\n{context}"
            messages.append({"role": "user", "content": context_message})
        
        # Add chat history (last 10 messages for context) - safely get from session state
        chat_messages = st.session_state.get('chat_messages', [])
        recent_messages = chat_messages[-10:] if chat_messages else []
        for msg in recent_messages:
            messages.append({"role": msg["role"], "content": msg["content"]})
        
        # Add current user message
        messages.append({"role": "user", "content": user_message})
        
        # Try models in order of preference
        last_error = None
        for model in OPENAI_MODELS:
            try:
                response = openai.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_tokens=2000
                )
                return response.choices[0].message.content
            except Exception as model_error:
                last_error = model_error
                continue
        
        # If all models failed
        return f"❌ **AI Service Error**: {str(last_error)}\n\nPlease try again later or check your API key configuration."
        
    except Exception as e:
        return f"❌ **Error**: {str(e)}\n\nPlease check your OpenAI API key configuration."

def analyze_scan_results(scan_type, results):
    """Analyze scan results with AI"""
    context_prompt = f"""
    Analyze these {scan_type} scan results and provide:
    1. Risk assessment and severity levels
    2. Detailed vulnerability explanations
    3. Specific remediation steps
    4. Compliance framework mapping
    5. Additional security recommendations
    
    Scan Results:
    {json.dumps(results, indent=2)}
    """
    
    return get_ai_response("Please analyze these scan results comprehensively.", context_prompt)

def get_security_recommendations(target_type, target_info):
    """Get security recommendations for specific targets"""
    prompt = f"""
    Provide comprehensive security recommendations for this {target_type}:
    
    Target Information:
    {json.dumps(target_info, indent=2)}
    
    Please include:
    1. Security hardening steps
    2. Monitoring recommendations
    3. Compliance considerations
    4. Risk mitigation strategies
    """
    
    return get_ai_response(prompt)

def render_chat_interface():
    """Render the AI chat interface"""
    st.title("🤖 AI Security Chat Assistant")
    
    initialize_chat()
    
    # Chat container
    chat_container = st.container()
    
    with chat_container:
        for message in st.session_state.chat_messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
    
    # Chat input
    if prompt := st.chat_input("Ask me about cybersecurity..."):
        # Add user message
        st.session_state.chat_messages.append({"role": "user", "content": prompt})
        
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Get AI response
        with st.chat_message("assistant"):
            with st.spinner("🧠 Analyzing security context..."):
                response = get_ai_response(prompt)
                st.markdown(response)
                
                # Add assistant response to chat history
                st.session_state.chat_messages.append({"role": "assistant", "content": response})
    
    # Sidebar with quick actions
    with st.sidebar:
        st.markdown("### 🚀 Quick Security Actions")
        
        if st.button("🔍 Analyze Last Scan"):
            user_info = st.session_state.get('user_info', {})
            if user_info:
                from database import get_user_scans
                recent_scans = get_user_scans(user_info['id'], 1)
                if recent_scans:
                    scan = recent_scans[0]
                    prompt = f"Analyze my recent {scan['scan_type']} scan of {scan['target']}"
                    st.session_state.chat_messages.append({"role": "user", "content": prompt})
                    
                    with st.spinner("🧠 Analyzing scan results..."):
                        response = analyze_scan_results(scan['scan_type'], scan['results'])
                        st.session_state.chat_messages.append({"role": "assistant", "content": response})
                    st.rerun()
                else:
                    st.warning("No recent scans found")
            else:
                st.error("Please log in first")
        
        if st.button("🛡️ Security Best Practices"):
            prompt = "What are the top 10 cybersecurity best practices for organizations in 2025?"
            st.session_state.chat_messages.append({"role": "user", "content": prompt})
            
            with st.spinner("🧠 Generating recommendations..."):
                response = get_ai_response(prompt)
                st.session_state.chat_messages.append({"role": "assistant", "content": response})
            st.rerun()
        
        if st.button("🚨 Incident Response Guide"):
            prompt = "Provide a comprehensive incident response checklist for a potential security breach"
            st.session_state.chat_messages.append({"role": "user", "content": prompt})
            
            with st.spinner("🧠 Creating incident response guide..."):
                response = get_ai_response(prompt)
                st.session_state.chat_messages.append({"role": "assistant", "content": response})
            st.rerun()
        
        if st.button("🔄 Clear Chat"):
            st.session_state.chat_messages = [st.session_state.chat_messages[0]]  # Keep welcome message
            st.rerun()

def get_vulnerability_explanation(vulnerability_name):
    """Get detailed explanation of a specific vulnerability"""
    prompt = f"""
    Provide a comprehensive analysis of the {vulnerability_name} vulnerability including:
    1. Technical description and how it works
    2. Potential impact and risk level
    3. Common attack vectors
    4. Detection methods
    5. Remediation steps
    6. Prevention strategies
    """
    
    return get_ai_response(prompt)
