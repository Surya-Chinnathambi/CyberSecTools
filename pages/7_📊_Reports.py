import streamlit as st
import os
from report_generator import generate_scan_report, save_report_record, get_user_reports
from auth import check_authentication
from utils import format_timestamp, format_file_size

# Page configuration
st.set_page_config(
    page_title="Reports - CyberSec Platform",
    page_icon="📊",
    layout="wide"
)

# Check authentication
if not check_authentication():
    st.stop()

def render_reports_page():
    """Render reports management page"""
    st.title("📊 Security Assessment Reports")
    st.markdown("**Generate comprehensive PDF reports from your security scans**")
    
    user_info = st.session_state.get('user_info', {})
    if not user_info:
        st.error("User information not available")
        return
    
    # Check user tier
    user_role = user_info.get('role', 'free')
    
    if user_role == 'free':
        st.warning("⚠️ **Report Generation is a Pro Feature**")
        st.info("Upgrade to Professional or Enterprise plan to generate detailed PDF reports")
        st.markdown("**Pro Features Include:**")
        st.markdown("• Executive summary reports")
        st.markdown("• Technical vulnerability details") 
        st.markdown("• Compliance framework mapping")
        st.markdown("• Remediation recommendations")
        
        if st.button("🚀 Upgrade to Pro"):
            st.switch_page("pages/8_💳_Billing.py")
        return
    
    # Report generation section
    tab1, tab2 = st.tabs(["🔄 Generate Report", "📄 Report History"])
    
    with tab1:
        st.markdown("### 🔄 Generate New Report")
        
        col1, col2 = st.columns(2)
        
        with col1:
            report_name = st.text_input(
                "Report Name",
                value="Security Assessment Report",
                help="Enter a descriptive name for your report"
            )
            
            report_type = st.selectbox(
                "Report Type",
                [
                    "Executive Summary",
                    "Technical Assessment", 
                    "Compliance Report",
                    "Vulnerability Analysis",
                    "Full Security Audit"
                ],
                help="Select the type of report to generate"
            )
        
        with col2:
            include_charts = st.checkbox("📊 Include Charts & Graphs", value=True)
            include_remediation = st.checkbox("🛠️ Include Remediation Steps", value=True)
            include_compliance = st.checkbox("✅ Include Compliance Mapping", value=True)
            include_executive_summary = st.checkbox("👔 Executive Summary", value=True)
        
        # Report scope
        st.markdown("### 🎯 Report Scope")
        
        scope_option = st.radio(
            "Include Data From:",
            [
                "All My Scans",
                "Last 30 Days", 
                "Last 7 Days",
                "Custom Date Range"
            ],
            horizontal=True
        )
        
        if scope_option == "Custom Date Range":
            col1, col2 = st.columns(2)
            with col1:
                start_date = st.date_input("Start Date")
            with col2:
                end_date = st.date_input("End Date")
        
        # Generate report button
        if st.button("🚀 Generate Report", type="primary", use_container_width=True):
            if not report_name.strip():
                st.error("Please enter a report name")
                return
            
            with st.spinner("📊 Generating comprehensive security report..."):
                try:
                    # Generate the report
                    report_file = generate_scan_report(user_info['id'], None, report_name)
                    
                    # Save report record
                    save_report_record(user_info['id'], report_name, report_file, report_type.lower())
                    
                    st.success("✅ Report generated successfully!")
                    
                    # Provide download link
                    if os.path.exists(report_file):
                        with open(report_file, "rb") as file:
                            st.download_button(
                                label="📥 Download Report (PDF)",
                                data=file.read(),
                                file_name=os.path.basename(report_file),
                                mime="application/pdf",
                                type="primary"
                            )
                    
                    # Show report preview
                    st.markdown("### 📋 Report Generated")
                    st.info(f"**Report Name:** {report_name}")
                    st.info(f"**File Location:** {report_file}")
                    st.info(f"**Report Type:** {report_type}")
                    
                except Exception as e:
                    st.error(f"❌ Report generation failed: {str(e)}")
    
    with tab2:
        st.markdown("### 📄 Report History")
        
        # Get user reports
        reports = get_user_reports(user_info['id'])
        
        if not reports:
            st.info("📝 No reports generated yet")
            st.markdown("Generate your first security report using the **Generate Report** tab above.")
            return
        
        # Reports table
        st.markdown(f"**Total Reports: {len(reports)}**")
        
        for i, report in enumerate(reports):
            with st.expander(f"📊 {report['report_name']} - {format_timestamp(report['created_at'])}"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**Name:** {report['report_name']}")
                    st.write(f"**Type:** {report['report_type'].title()}")
                
                with col2:
                    st.write(f"**Created:** {format_timestamp(report['created_at'])}")
                    
                    # Check if file exists and get size
                    if os.path.exists(report['file_path']):
                        file_size = os.path.getsize(report['file_path'])
                        st.write(f"**Size:** {format_file_size(file_size)}")
                    else:
                        st.write(f"**Size:** File not found")
                
                with col3:
                    # Download button
                    if os.path.exists(report['file_path']):
                        try:
                            with open(report['file_path'], "rb") as file:
                                st.download_button(
                                    label="📥 Download",
                                    data=file.read(),
                                    file_name=f"{report['report_name']}.pdf",
                                    mime="application/pdf",
                                    key=f"download_{report['id']}"
                                )
                        except Exception as e:
                            st.error(f"Download error: {str(e)}")
                    else:
                        st.error("File not found")
                
                # Report actions
                st.markdown("**Actions:**")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("🔄 Regenerate", key=f"regen_{report['id']}"):
                        st.info("Regeneration feature coming soon")
                
                with col2:
                    if st.button("📧 Email", key=f"email_{report['id']}"):
                        st.info("Email feature coming soon")
                
                with col3:
                    if st.button("🗑️ Delete", key=f"delete_{report['id']}"):
                        st.warning("Delete confirmation coming soon")

# Render the page
render_reports_page()
