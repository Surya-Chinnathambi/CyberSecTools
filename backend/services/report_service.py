from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from datetime import datetime
import json
import os

from utils.database import get_user_scans

def generate_security_report(user_id: int, report_name: str = "Security Assessment") -> str:
    scans = get_user_scans(user_id, limit=50)
    
    if not scans:
        raise ValueError("No scan data available for report generation")
    
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/{report_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    doc = SimpleDocTemplate(filename, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    title = Paragraph(f"<b>{report_name}</b>", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 0.5*inch))
    
    subtitle = Paragraph(
        f"Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
        styles['Normal']
    )
    story.append(subtitle)
    story.append(Spacer(1, 0.5*inch))
    
    summary = Paragraph("<b>Executive Summary</b>", styles['Heading1'])
    story.append(summary)
    
    summary_text = f"""
    This comprehensive security assessment analyzed {len(scans)} targets using multiple 
    scanning techniques. The assessment identified various security concerns that require attention.
    """
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 0.3*inch))
    
    findings = Paragraph("<b>Key Findings</b>", styles['Heading2'])
    story.append(findings)
    
    for scan in scans[:10]:
        scan_info = f"""
        <b>Scan Type:</b> {scan['scan_type']}<br/>
        <b>Target:</b> {scan['target']}<br/>
        <b>Date:</b> {scan['created_at'][:19]}<br/>
        <b>Status:</b> {scan['status']}
        """
        story.append(Paragraph(scan_info, styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
    
    doc.build(story)
    return filename
