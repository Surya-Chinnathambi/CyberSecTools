import requests
import streamlit as st
import json
from datetime import datetime, timedelta
import time
from database import cache_cve_data, get_cached_cve_data

# NVD API Configuration
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = ""  # Optional: Add NVD API key for higher rate limits

def get_cvss_color(score):
    """Get color code for CVSS score"""
    if score >= 9.0:
        return "🔴"  # Critical
    elif score >= 7.0:
        return "🟠"  # High
    elif score >= 4.0:
        return "🟡"  # Medium
    elif score >= 0.1:
        return "🟢"  # Low
    else:
        return "⚪"  # None/Unknown

def get_severity_from_score(score):
    """Get severity level from CVSS score"""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score >= 0.1:
        return "LOW"
    else:
        return "NONE"

def search_cves_by_keyword(keyword, limit=20):
    """Search CVEs by keyword using NVD API"""
    try:
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': limit,
            'startIndex': 0
        }
        
        headers = {}
        if API_KEY:
            headers['apiKey'] = API_KEY
        
        response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = []
            
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'Unknown')
                
                # Get description
                descriptions = cve.get('descriptions', [])
                description = ""
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Get CVSS score
                metrics = cve.get('metrics', {})
                cvss_score = 0.0
                
                # Try CVSS v3.1 first, then v3.0, then v2.0
                for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if version in metrics and metrics[version]:
                        metric = metrics[version][0]
                        if 'cvssData' in metric:
                            cvss_score = metric['cvssData'].get('baseScore', 0.0)
                            break
                
                # Get dates
                published = cve.get('published', '')
                modified = cve.get('lastModified', '')
                
                vulnerability = {
                    'cve_id': cve_id,
                    'description': description,
                    'cvss_score': cvss_score,
                    'severity': get_severity_from_score(cvss_score),
                    'published_date': published,
                    'modified_date': modified
                }
                
                vulnerabilities.append(vulnerability)
                
                # Cache the CVE data
                cache_cve_data(
                    cve_id, description, cvss_score,
                    get_severity_from_score(cvss_score),
                    published, modified
                )
            
            return vulnerabilities
            
        else:
            st.error(f"NVD API Error: {response.status_code}")
            return []
            
    except Exception as e:
        st.error(f"Error searching CVEs: {str(e)}")
        return []

def get_cve_details(cve_id):
    """Get detailed information for a specific CVE"""
    # First check cache
    cached_data = get_cached_cve_data(cve_id)
    if cached_data:
        return cached_data
    
    try:
        params = {
            'cveId': cve_id
        }
        
        headers = {}
        if API_KEY:
            headers['apiKey'] = API_KEY
        
        response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('vulnerabilities'):
                item = data['vulnerabilities'][0]
                cve = item.get('cve', {})
                
                # Get description
                descriptions = cve.get('descriptions', [])
                description = ""
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Get CVSS score and vector
                metrics = cve.get('metrics', {})
                cvss_score = 0.0
                cvss_vector = ""
                
                for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if version in metrics and metrics[version]:
                        metric = metrics[version][0]
                        if 'cvssData' in metric:
                            cvss_score = metric['cvssData'].get('baseScore', 0.0)
                            cvss_vector = metric['cvssData'].get('vectorString', '')
                            break
                
                # Get references
                references = []
                for ref in cve.get('references', []):
                    references.append({
                        'url': ref.get('url', ''),
                        'source': ref.get('source', ''),
                        'tags': ref.get('tags', [])
                    })
                
                cve_details = {
                    'cve_id': cve_id,
                    'description': description,
                    'cvss_score': cvss_score,
                    'cvss_vector': cvss_vector,
                    'severity': get_severity_from_score(cvss_score),
                    'published_date': cve.get('published', ''),
                    'modified_date': cve.get('lastModified', ''),
                    'references': references
                }
                
                # Cache the detailed data
                cache_cve_data(
                    cve_id, description, cvss_score,
                    get_severity_from_score(cvss_score),
                    cve.get('published', ''), cve.get('lastModified', '')
                )
                
                return cve_details
        
        return None
        
    except Exception as e:
        st.error(f"Error getting CVE details: {str(e)}")
        return None

def get_recent_cves(days=7, limit=50):
    """Get recent CVEs from the last N days"""
    try:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            'resultsPerPage': limit,
            'startIndex': 0
        }
        
        headers = {}
        if API_KEY:
            headers['apiKey'] = API_KEY
        
        response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = []
            
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'Unknown')
                
                # Get description
                descriptions = cve.get('descriptions', [])
                description = ""
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Get CVSS score
                metrics = cve.get('metrics', {})
                cvss_score = 0.0
                
                for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if version in metrics and metrics[version]:
                        metric = metrics[version][0]
                        if 'cvssData' in metric:
                            cvss_score = metric['cvssData'].get('baseScore', 0.0)
                            break
                
                vulnerability = {
                    'cve_id': cve_id,
                    'description': description[:200] + "..." if len(description) > 200 else description,
                    'cvss_score': cvss_score,
                    'severity': get_severity_from_score(cvss_score),
                    'published_date': cve.get('published', ''),
                }
                
                vulnerabilities.append(vulnerability)
            
            # Sort by CVSS score (highest first)
            vulnerabilities.sort(key=lambda x: x['cvss_score'], reverse=True)
            return vulnerabilities
            
        else:
            st.error(f"NVD API Error: {response.status_code}")
            return []
            
    except Exception as e:
        st.error(f"Error getting recent CVEs: {str(e)}")
        return []

def render_cve_database():
    """Render CVE database interface"""
    st.title("🛡️ CVE Vulnerability Database")
    st.markdown("**Real-time vulnerability data from the National Vulnerability Database (NVD)**")
    
    # Search interface
    tab1, tab2, tab3 = st.tabs(["🔍 Search CVEs", "📅 Recent CVEs", "🎯 CVE Details"])
    
    with tab1:
        st.markdown("### 🔍 Search Vulnerabilities")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            search_term = st.text_input(
                "Search CVEs",
                placeholder="Enter keywords (e.g., 'apache', 'windows', 'sql injection')",
                help="Search for CVEs by keyword, product name, or vulnerability type"
            )
        
        with col2:
            limit = st.selectbox("Results Limit", [10, 20, 50, 100], index=1)
        
        if st.button("🚀 Search CVEs", type="primary"):
            if search_term:
                with st.spinner("🔍 Searching CVE database..."):
                    results = search_cves_by_keyword(search_term, limit)
                    
                    if results:
                        st.success(f"✅ Found {len(results)} vulnerabilities")
                        display_cve_results(results)
                    else:
                        st.warning("No vulnerabilities found for the search term")
            else:
                st.error("Please enter a search term")
    
    with tab2:
        st.markdown("### 📅 Recent Vulnerabilities")
        
        col1, col2 = st.columns(2)
        with col1:
            days = st.selectbox("Time Period", [1, 3, 7, 14, 30], index=2, format_func=lambda x: f"Last {x} days")
        with col2:
            limit = st.selectbox("Limit", [20, 50, 100], index=1, key="recent_limit")
        
        if st.button("🔄 Get Recent CVEs", type="primary"):
            with st.spinner("📡 Fetching recent vulnerabilities..."):
                results = get_recent_cves(days, limit)
                
                if results:
                    st.success(f"✅ Found {len(results)} recent vulnerabilities")
                    display_cve_results(results)
                else:
                    st.warning("No recent vulnerabilities found")
    
    with tab3:
        st.markdown("### 🎯 CVE Details")
        
        cve_id = st.text_input(
            "CVE ID",
            placeholder="CVE-2024-12345",
            help="Enter a specific CVE ID to get detailed information"
        )
        
        if st.button("🔍 Get CVE Details", type="primary"):
            if cve_id:
                with st.spinner("📊 Fetching CVE details..."):
                    details = get_cve_details(cve_id)
                    
                    if details:
                        display_cve_details(details)
                    else:
                        st.error("CVE not found or API error")
            else:
                st.error("Please enter a CVE ID")

def display_cve_results(results):
    """Display CVE search results"""
    for cve in results:
        severity_color = get_cvss_color(cve['cvss_score'])
        
        with st.expander(f"{severity_color} {cve['cve_id']} - {cve['severity']} ({cve['cvss_score']})"):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**Description:**")
                st.write(cve['description'])
                
                if st.button(f"🔍 View Details", key=f"details_{cve['cve_id']}"):
                    details = get_cve_details(cve['cve_id'])
                    if details:
                        st.session_state[f"cve_details_{cve['cve_id']}"] = details
            
            with col2:
                st.metric("CVSS Score", f"{cve['cvss_score']}/10")
                st.write(f"**Severity:** {cve['severity']}")
                if cve['published_date']:
                    pub_date = cve['published_date'][:10]  # Extract date part
                    st.write(f"**Published:** {pub_date}")
            
            # Show details if available
            if f"cve_details_{cve['cve_id']}" in st.session_state:
                details = st.session_state[f"cve_details_{cve['cve_id']}"]
                display_cve_details_inline(details)

def display_cve_details(details):
    """Display detailed CVE information"""
    st.markdown(f"## {details['cve_id']}")
    
    # Metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_color = get_cvss_color(details['cvss_score'])
        st.metric("CVSS Score", f"{details['cvss_score']}/10", delta=None)
    
    with col2:
        st.metric("Severity", details['severity'])
    
    with col3:
        if details['published_date']:
            pub_date = details['published_date'][:10]
            st.metric("Published", pub_date)
    
    # Description
    st.markdown("### 📋 Description")
    st.write(details['description'])
    
    # CVSS Vector
    if details.get('cvss_vector'):
        st.markdown("### 🎯 CVSS Vector")
        st.code(details['cvss_vector'])
    
    # References
    if details.get('references'):
        st.markdown("### 🔗 References")
        for ref in details['references'][:10]:  # Limit to first 10 references
            st.markdown(f"- [{ref['source']}]({ref['url']})")
            if ref['tags']:
                st.caption(f"Tags: {', '.join(ref['tags'])}")

def display_cve_details_inline(details):
    """Display CVE details inline within an expander"""
    if details.get('cvss_vector'):
        st.markdown("**CVSS Vector:**")
        st.code(details['cvss_vector'])
    
    if details.get('references'):
        st.markdown("**References:**")
        for ref in details['references'][:3]:  # Limit to first 3 references
            st.markdown(f"- [{ref['source']}]({ref['url']})")

def get_cve_statistics():
    """Get CVE statistics for dashboard"""
    try:
        # Get recent high-severity CVEs
        recent_high = get_recent_cves(days=30, limit=100)
        high_severity = [cve for cve in recent_high if cve['cvss_score'] >= 7.0]
        critical_severity = [cve for cve in recent_high if cve['cvss_score'] >= 9.0]
        
        return {
            'total_recent': len(recent_high),
            'high_severity': len(high_severity),
            'critical_severity': len(critical_severity),
            'avg_score': sum(cve['cvss_score'] for cve in recent_high) / len(recent_high) if recent_high else 0
        }
    except:
        return {
            'total_recent': 0,
            'high_severity': 0,
            'critical_severity': 0,
            'avg_score': 0
        }
