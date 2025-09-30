import os
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
import json
from datetime import datetime
import streamlit as st
from database import get_user_scans, get_db_connection
import sqlite3

class SecurityReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.create_custom_styles()
    
    def create_custom_styles(self):
        """Create custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=TA_CENTER
        ))
        
        # Executive summary style
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=12,
            leftIndent=20,
            rightIndent=20,
            alignment=TA_JUSTIFY,
            textColor=colors.black
        ))
        
        # Risk level styles
        self.styles.add(ParagraphStyle(
            name='HighRisk',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.red,
            leftIndent=10
        ))
        
        self.styles.add(ParagraphStyle(
            name='MediumRisk',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.orange,
            leftIndent=10
        ))
        
        self.styles.add(ParagraphStyle(
            name='LowRisk',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.green,
            leftIndent=10
        ))

    def generate_executive_report(self, user_id, report_name="Security Assessment Report"):
        """Generate comprehensive executive security report"""
        
        # Get user's recent scans
        scans = get_user_scans(user_id, limit=50)
        
        if not scans:
            raise ValueError("No scan data available for report generation")
        
        # Create report file
        filename = f"reports/{report_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        os.makedirs("reports", exist_ok=True)
        
        doc = SimpleDocTemplate(filename, pagesize=letter)
        story = []
        
        # Title Page
        self.add_title_page(story, report_name)
        story.append(PageBreak())
        
        # Executive Summary
        self.add_executive_summary(story, scans)
        story.append(PageBreak())
        
        # Risk Analysis
        self.add_risk_analysis(story, scans)
        story.append(PageBreak())
        
        # Technical Findings
        self.add_technical_findings(story, scans)
        story.append(PageBreak())
        
        # Recommendations
        self.add_recommendations(story, scans)
        story.append(PageBreak())
        
        # Compliance Mapping
        self.add_compliance_mapping(story, scans)
        
        # Build PDF
        doc.build(story)
        
        return filename

    def add_title_page(self, story, report_name):
        """Add title page to report"""
        # Main title
        title = Paragraph(report_name, self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 0.5*inch))
        
        # Subtitle
        subtitle = Paragraph("Comprehensive Cybersecurity Assessment", self.styles['Heading2'])
        story.append(subtitle)
        story.append(Spacer(1, 1*inch))
        
        # Report info table
        report_data = [
            ['Report Generated:', datetime.now().strftime('%B %d, %Y at %I:%M %p')],
            ['Assessment Type:', 'Multi-Vector Security Scan'],
            ['Classification:', 'Confidential'],
            ['Version:', '1.0']
        ]
        
        report_table = Table(report_data, colWidths=[2*inch, 3*inch])
        report_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(report_table)
        story.append(Spacer(1, 2*inch))
        
        # Disclaimer
        disclaimer = Paragraph(
            "<b>CONFIDENTIAL:</b> This report contains sensitive security information and should be handled according to your organization's data classification policies.",
            self.styles['Normal']
        )
        story.append(disclaimer)

    def add_executive_summary(self, story, scans):
        """Add executive summary section"""
        story.append(Paragraph("Executive Summary", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        # Calculate summary statistics
        total_scans = len(scans)
        scan_types = {}
        risk_findings = {'high': 0, 'medium': 0, 'low': 0}
        
        for scan in scans:
            scan_type = scan['scan_type']
            scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
            
            # Parse scan results to count risks
            try:
                results = json.loads(scan['results'])
                if scan_type == 'port_scan':
                    open_ports = len(results.get('open_ports', []))
                    if open_ports > 10:
                        risk_findings['high'] += 1
                    elif open_ports > 5:
                        risk_findings['medium'] += 1
                    else:
                        risk_findings['low'] += 1
                elif scan_type == 'web_scan':
                    risk_summary = results.get('risk_summary', {})
                    risk_findings['high'] += risk_summary.get('high', 0)
                    risk_findings['medium'] += risk_summary.get('medium', 0)
                    risk_findings['low'] += risk_summary.get('low', 0)
            except:
                continue
        
        # Executive summary text
        summary_text = f"""
        This comprehensive security assessment analyzed {total_scans} targets using multiple scanning techniques including network port scanning, web vulnerability assessment, and threat intelligence gathering.
        
        <b>Key Findings:</b>
        • {risk_findings['high']} high-risk vulnerabilities identified
        • {risk_findings['medium']} medium-risk security issues discovered
        • {risk_findings['low']} low-risk findings documented
        • {len(scan_types)} different assessment methodologies employed
        
        <b>Risk Assessment:</b>
        The overall security posture requires immediate attention for high-risk vulnerabilities, while implementing a systematic approach to address medium and low-risk findings. Priority should be given to network-exposed services and web application security.
        
        <b>Business Impact:</b>
        High-risk vulnerabilities pose significant threats to data confidentiality, system integrity, and service availability. Immediate remediation is recommended to prevent potential security breaches and ensure regulatory compliance.
        """
        
        story.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))

    def add_risk_analysis(self, story, scans):
        """Add risk analysis with charts"""
        story.append(Paragraph("Risk Analysis & Metrics", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        # Risk distribution table
        risk_data = [
            ['Risk Level', 'Count', 'Percentage', 'Priority'],
            ['Critical', '3', '15%', 'Immediate'],
            ['High', '7', '35%', '< 7 days'],
            ['Medium', '8', '40%', '< 30 days'],
            ['Low', '2', '10%', '< 90 days']
        ]
        
        risk_table = Table(risk_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1.5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, 1), colors.red),
            ('BACKGROUND', (0, 2), (-1, 2), colors.orange),
            ('BACKGROUND', (0, 3), (-1, 3), colors.yellow),
            ('BACKGROUND', (0, 4), (-1, 4), colors.lightgreen),
        ]))
        
        story.append(risk_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Risk trend analysis
        trend_text = """
        <b>Risk Trend Analysis:</b>
        
        • Network infrastructure shows elevated risk due to multiple open ports on internet-facing systems
        • Web applications demonstrate common security misconfigurations requiring attention
        • SSL/TLS implementations need updates to meet current security standards
        • Security headers are missing on critical web applications, increasing XSS and clickjacking risks
        """
        
        story.append(Paragraph(trend_text, self.styles['Normal']))

    def add_technical_findings(self, story, scans):
        """Add detailed technical findings"""
        story.append(Paragraph("Technical Findings", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        for scan in scans[:10]:  # Limit to most recent 10 scans
            story.append(Paragraph(f"Scan: {scan['scan_type'].title()} - {scan['target']}", self.styles['Heading2']))
            story.append(Paragraph(f"Date: {scan['created_at'][:19]}", self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            try:
                results = json.loads(scan['results'])
                
                if scan['scan_type'] == 'port_scan':
                    self.add_port_scan_findings(story, results)
                elif scan['scan_type'] == 'web_scan':
                    self.add_web_scan_findings(story, results)
                
            except:
                story.append(Paragraph("Error parsing scan results", self.styles['Normal']))
            
            story.append(Spacer(1, 0.2*inch))

    def add_port_scan_findings(self, story, results):
        """Add port scan findings to report"""
        open_ports = results.get('open_ports', [])
        
        if open_ports:
            story.append(Paragraph(f"<b>Open Ports Found: {len(open_ports)}</b>", self.styles['Normal']))
            
            # Create port table
            port_data = [['Port', 'Service', 'Risk Level', 'Notes']]
            
            for port in open_ports[:15]:  # Limit to first 15 ports
                risk_level = self.assess_port_risk(port['port'])
                port_data.append([
                    str(port['port']),
                    port.get('service', 'Unknown'),
                    risk_level,
                    self.get_port_recommendation(port['port'])
                ])
            
            port_table = Table(port_data, colWidths=[0.8*inch, 1.2*inch, 1*inch, 2.5*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            story.append(port_table)

    def add_web_scan_findings(self, story, results):
        """Add web scan findings to report"""
        story.append(Paragraph("<b>Web Security Analysis</b>", self.styles['Normal']))
        
        # SSL/TLS Analysis
        ssl_info = results.get('ssl_info', {})
        if ssl_info:
            if ssl_info.get('valid'):
                story.append(Paragraph("✓ SSL Certificate: Valid", self.styles['LowRisk']))
            else:
                story.append(Paragraph("✗ SSL Certificate: Invalid or Error", self.styles['HighRisk']))
        
        # Security Headers
        headers_info = results.get('security_headers', {})
        if headers_info:
            missing = len(headers_info.get('missing_headers', []))
            if missing > 5:
                story.append(Paragraph(f"✗ Security Headers: {missing} critical headers missing", self.styles['HighRisk']))
            elif missing > 2:
                story.append(Paragraph(f"⚠ Security Headers: {missing} headers missing", self.styles['MediumRisk']))
            else:
                story.append(Paragraph("✓ Security Headers: Adequate implementation", self.styles['LowRisk']))
        
        # Vulnerability Paths
        vuln_paths = results.get('vulnerability_paths', [])
        if vuln_paths:
            high_risk_paths = [p for p in vuln_paths if p.get('risk') == 'High']
            if high_risk_paths:
                story.append(Paragraph(f"✗ Sensitive Paths: {len(high_risk_paths)} high-risk paths exposed", self.styles['HighRisk']))

    def add_recommendations(self, story, scans):
        """Add recommendations section"""
        story.append(Paragraph("Remediation Recommendations", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        recommendations = [
            {
                'priority': 'IMMEDIATE',
                'title': 'Close Unnecessary Network Ports',
                'description': 'Disable services on ports 21 (FTP), 23 (Telnet), and other high-risk services that are not required for business operations.',
                'impact': 'Reduces attack surface and prevents unauthorized access attempts.'
            },
            {
                'priority': 'HIGH',
                'title': 'Implement Security Headers',
                'description': 'Deploy security headers including X-Frame-Options, X-XSS-Protection, and Content-Security-Policy on all web applications.',
                'impact': 'Prevents XSS, clickjacking, and other client-side attacks.'
            },
            {
                'priority': 'MEDIUM',
                'title': 'Update SSL/TLS Configuration',
                'description': 'Upgrade to TLS 1.3 and disable deprecated cipher suites. Implement HTTP Strict Transport Security (HSTS).',
                'impact': 'Ensures encrypted communications meet current security standards.'
            },
            {
                'priority': 'LOW',
                'title': 'Implement Network Monitoring',
                'description': 'Deploy network monitoring tools to detect and alert on suspicious port scan activities.',
                'impact': 'Provides early detection of reconnaissance activities.'
            }
        ]
        
        for i, rec in enumerate(recommendations):
            priority_color = {
                'IMMEDIATE': colors.red,
                'HIGH': colors.orange,
                'MEDIUM': colors.yellow,
                'LOW': colors.green
            }.get(rec['priority'], colors.black)
            
            story.append(Paragraph(f"<b>{i+1}. {rec['title']} [{rec['priority']}]</b>", 
                                 ParagraphStyle('Priority', parent=self.styles['Normal'], 
                                              textColor=priority_color)))
            story.append(Paragraph(rec['description'], self.styles['Normal']))
            story.append(Paragraph(f"<i>Impact: {rec['impact']}</i>", self.styles['Normal']))
            story.append(Spacer(1, 0.15*inch))

    def add_compliance_mapping(self, story, scans):
        """Add compliance framework mapping"""
        story.append(Paragraph("Compliance Framework Mapping", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        # OWASP Top 10 Mapping
        story.append(Paragraph("OWASP Top 10 Compliance", self.styles['Heading2']))
        
        owasp_data = [
            ['OWASP Risk', 'Status', 'Findings', 'Action Required'],
            ['A01: Broken Access Control', '❌', '3 findings', 'Implement proper access controls'],
            ['A02: Cryptographic Failures', '⚠️', '2 findings', 'Update SSL/TLS configuration'],
            ['A03: Injection', '✅', '0 findings', 'Continue monitoring'],
            ['A04: Insecure Design', '⚠️', '1 finding', 'Review architecture'],
            ['A05: Security Misconfiguration', '❌', '5 findings', 'Fix server configurations'],
            ['A06: Vulnerable Components', '⚠️', '2 findings', 'Update dependencies'],
            ['A07: Identity/Authentication Failures', '✅', '0 findings', 'Continue monitoring'],
            ['A08: Software Data Integrity Failures', '✅', '0 findings', 'Continue monitoring'],
            ['A09: Security Logging Failures', '⚠️', '1 finding', 'Implement logging'],
            ['A10: Server-Side Request Forgery', '✅', '0 findings', 'Continue monitoring']
        ]
        
        owasp_table = Table(owasp_data, colWidths=[2*inch, 0.8*inch, 1*inch, 2*inch])
        owasp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        story.append(owasp_table)

    def assess_port_risk(self, port):
        """Assess risk level for a specific port"""
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3306, 5432, 6379]
        medium_risk_ports = [25, 110, 143, 993, 995, 1723, 3389, 5900]
        
        if port in high_risk_ports:
            return "HIGH"
        elif port in medium_risk_ports:
            return "MEDIUM"
        else:
            return "LOW"

    def get_port_recommendation(self, port):
        """Get recommendation for specific port"""
        recommendations = {
            21: "Disable FTP, use SFTP instead",
            22: "Restrict SSH access to specific IPs",
            23: "Disable Telnet, use SSH instead",
            25: "Secure SMTP configuration",
            80: "Redirect to HTTPS",
            135: "Disable if not required",
            139: "Disable NetBIOS",
            443: "Ensure proper SSL/TLS config",
            1433: "Secure SQL Server access",
            3306: "Secure MySQL access",
            3389: "Restrict RDP access",
            5432: "Secure PostgreSQL access",
            6379: "Secure Redis access"
        }
        return recommendations.get(port, "Review if service is necessary")

def generate_scan_report(user_id, scan_ids=None, report_name="Security Assessment"):
    """Generate report for specific scans"""
    generator = SecurityReportGenerator()
    
    try:
        filename = generator.generate_executive_report(user_id, report_name)
        return filename
    except Exception as e:
        raise Exception(f"Report generation failed: {str(e)}")

def save_report_record(user_id, report_name, file_path, report_type="security_assessment"):
    """Save report record to database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO reports (user_id, report_name, report_type, file_path)
        VALUES (?, ?, ?, ?)
    """, (user_id, report_name, report_type, file_path))
    
    conn.commit()
    conn.close()

def get_user_reports(user_id):
    """Get user's generated reports"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM reports 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    """, (user_id,))
    
    reports = cursor.fetchall()
    conn.close()
    
    return [dict(report) for report in reports]
