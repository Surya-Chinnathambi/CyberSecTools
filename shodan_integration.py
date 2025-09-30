import requests
import streamlit as st
import json
import os
from datetime import datetime
import folium
from streamlit_folium import st_folium

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SHODAN_BASE_URL = "https://api.shodan.io"

def search_shodan(query, limit=100):
    """Search Shodan for hosts"""
    if not SHODAN_API_KEY:
        st.error("❌ Shodan API key not configured. Please set SHODAN_API_KEY environment variable.")
        return None
    
    try:
        url = f"{SHODAN_BASE_URL}/shodan/host/search"
        params = {
            'key': SHODAN_API_KEY,
            'query': query,
            'limit': limit
        }
        
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"Shodan API Error: {response.status_code}")
            return None
            
    except Exception as e:
        st.error(f"Error searching Shodan: {str(e)}")
        return None

def get_host_info(ip_address):
    """Get detailed information for a specific IP"""
    if not SHODAN_API_KEY:
        st.error("❌ Shodan API key not configured.")
        return None
    
    try:
        url = f"{SHODAN_BASE_URL}/shodan/host/{ip_address}"
        params = {'key': SHODAN_API_KEY}
        
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"Shodan API Error: {response.status_code}")
            return None
            
    except Exception as e:
        st.error(f"Error getting host info: {str(e)}")
        return None

def analyze_exposure_risk(host_data):
    """Analyze exposure risk based on Shodan data"""
    risk_factors = []
    risk_score = 0
    
    # Check for dangerous services
    dangerous_services = ['ftp', 'telnet', 'ssh', 'rdp', 'vnc', 'mongodb', 'elasticsearch', 'redis']
    
    for service in host_data.get('data', []):
        port = service.get('port', 0)
        product = service.get('product', '').lower()
        
        # High-risk ports
        if port in [21, 23, 1433, 3306, 5432, 6379, 9200, 27017]:
            risk_factors.append(f"High-risk port {port} open")
            risk_score += 3
        
        # Dangerous services
        for dangerous in dangerous_services:
            if dangerous in product:
                risk_factors.append(f"Potentially dangerous service: {product}")
                risk_score += 2
        
        # Default credentials indicators
        if 'default' in service.get('banner', '').lower():
            risk_factors.append("Potential default credentials detected")
            risk_score += 3
    
    # Location risk (data centers, cloud providers)
    org = host_data.get('org', '').lower()
    if any(provider in org for provider in ['amazon', 'google', 'microsoft', 'digitalocean']):
        risk_factors.append("Hosted on major cloud provider")
        risk_score += 1
    
    # Determine risk level
    if risk_score >= 8:
        risk_level = "🔴 CRITICAL"
    elif risk_score >= 5:
        risk_level = "🟠 HIGH"
    elif risk_score >= 2:
        risk_level = "🟡 MEDIUM"
    else:
        risk_level = "🟢 LOW"
    
    return {
        'risk_level': risk_level,
        'risk_score': risk_score,
        'risk_factors': risk_factors
    }

def render_shodan_intelligence():
    """Render Shodan intelligence interface"""
    st.title("🌍 Shodan Intelligence Platform")
    st.markdown("**Global internet exposure analysis and reconnaissance**")
    
    if not SHODAN_API_KEY:
        st.error("⚠️ **Shodan API Key Required**")
        st.info("To use Shodan Intelligence features, please set your SHODAN_API_KEY environment variable.")
        st.markdown("""
        **How to get a Shodan API key:**
        1. Visit [shodan.io](https://www.shodan.io/)
        2. Create a free account
        3. Go to your account page to find your API key
        4. Set the SHODAN_API_KEY environment variable
        """)
        return
    
    # Tabs for different search types
    tab1, tab2, tab3 = st.tabs(["🔍 Search Internet", "🎯 Host Analysis", "🗺️ Threat Map"])
    
    with tab1:
        st.markdown("### 🔍 Internet-wide Search")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            search_query = st.text_input(
                "Shodan Query",
                placeholder="port:22 country:US",
                help="Enter Shodan search query (e.g., 'apache', 'port:80', 'country:US')"
            )
        
        with col2:
            limit = st.selectbox("Results Limit", [50, 100, 200], index=1)
        
        # Query examples
        st.markdown("**Example Queries:**")
        examples = [
            "apache",
            "nginx",
            "port:22",
            "port:80 country:US", 
            "mongodb",
            "redis",
            "elasticsearch",
            "\"default password\""
        ]
        
        example_cols = st.columns(4)
        for i, example in enumerate(examples):
            with example_cols[i % 4]:
                if st.button(f"`{example}`", key=f"example_{i}"):
                    st.session_state.shodan_query = example
        
        # Use example query if selected
        if 'shodan_query' in st.session_state:
            search_query = st.session_state.shodan_query
            del st.session_state.shodan_query
        
        if st.button("🚀 Search Shodan", type="primary"):
            if search_query:
                with st.spinner("🔍 Searching global internet data..."):
                    results = search_shodan(search_query, limit)
                    
                    if results:
                        display_shodan_results(results)
            else:
                st.error("Please enter a search query")
    
    with tab2:
        st.markdown("### 🎯 Host Intelligence Analysis")
        
        ip_address = st.text_input(
            "IP Address",
            placeholder="8.8.8.8",
            help="Enter an IP address to get detailed intelligence"
        )
        
        if st.button("🔍 Analyze Host", type="primary"):
            if ip_address:
                with st.spinner("📊 Gathering host intelligence..."):
                    host_data = get_host_info(ip_address)
                    
                    if host_data:
                        display_host_analysis(host_data)
            else:
                st.error("Please enter an IP address")
    
    with tab3:
        st.markdown("### 🗺️ Global Threat Visualization")
        
        # Create a simple threat map
        if st.button("🌍 Generate Threat Map"):
            with st.spinner("🗺️ Creating global threat map..."):
                create_threat_map()

def display_shodan_results(results):
    """Display Shodan search results"""
    st.markdown("## 📊 Search Results")
    
    # Summary metrics
    total_results = results.get('total', 0)
    matches = results.get('matches', [])
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Found", f"{total_results:,}")
    
    with col2:
        st.metric("Displayed", len(matches))
    
    with col3:
        countries = set(match.get('location', {}).get('country_name', 'Unknown') for match in matches)
        st.metric("Countries", len(countries))
    
    # Country breakdown
    if matches:
        country_counts = {}
        for match in matches:
            country = match.get('location', {}).get('country_name', 'Unknown')
            country_counts[country] = country_counts.get(country, 0) + 1
        
        st.markdown("### 🌍 Geographic Distribution")
        for country, count in sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            st.write(f"**{country}:** {count} hosts")
    
    # Individual results
    st.markdown("### 🎯 Host Details")
    
    for i, match in enumerate(matches[:20]):  # Limit to first 20 for display
        ip = match.get('ip_str', 'Unknown')
        port = match.get('port', 'Unknown')
        org = match.get('org', 'Unknown')
        location = match.get('location', {})
        country = location.get('country_name', 'Unknown')
        city = location.get('city', 'Unknown')
        
        with st.expander(f"🌐 {ip}:{port} - {org} ({country})"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**IP Address:** {ip}")
                st.write(f"**Port:** {port}")
                st.write(f"**Organization:** {org}")
                st.write(f"**Location:** {city}, {country}")
            
            with col2:
                # Risk analysis
                risk_analysis = analyze_exposure_risk({'data': [match]})
                st.write(f"**Risk Level:** {risk_analysis['risk_level']}")
                st.write(f"**Risk Score:** {risk_analysis['risk_score']}/10")
                
                if risk_analysis['risk_factors']:
                    st.write("**Risk Factors:**")
                    for factor in risk_analysis['risk_factors'][:3]:
                        st.write(f"• {factor}")
            
            # Banner information
            banner = match.get('banner', '').strip()
            if banner:
                st.markdown("**Service Banner:**")
                st.code(banner[:500] + "..." if len(banner) > 500 else banner)

def display_host_analysis(host_data):
    """Display detailed host analysis"""
    st.markdown("## 🎯 Host Intelligence Report")
    
    # Basic information
    ip = host_data.get('ip_str', 'Unknown')
    org = host_data.get('org', 'Unknown')
    isp = host_data.get('isp', 'Unknown')
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("IP Address", ip)
    
    with col2:
        st.metric("Organization", org)
    
    with col3:
        open_ports = len(host_data.get('data', []))
        st.metric("Open Ports", open_ports)
    
    # Location information
    location = host_data.get('location', {})
    if location:
        st.markdown("### 🌍 Location Information")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.write(f"**Country:** {location.get('country_name', 'Unknown')}")
        
        with col2:
            st.write(f"**City:** {location.get('city', 'Unknown')}")
        
        with col3:
            st.write(f"**Region:** {location.get('region_code', 'Unknown')}")
        
        with col4:
            st.write(f"**Postal Code:** {location.get('postal_code', 'Unknown')}")
    
    # Risk analysis
    risk_analysis = analyze_exposure_risk(host_data)
    st.markdown("### ⚠️ Exposure Risk Assessment")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Risk Level", risk_analysis['risk_level'])
    
    with col2:
        st.metric("Risk Score", f"{risk_analysis['risk_score']}/10")
    
    if risk_analysis['risk_factors']:
        st.markdown("**Risk Factors:**")
        for factor in risk_analysis['risk_factors']:
            st.write(f"• {factor}")
    
    # Open ports and services
    services = host_data.get('data', [])
    if services:
        st.markdown("### 🔌 Open Ports & Services")
        
        for service in services:
            port = service.get('port', 'Unknown')
            product = service.get('product', 'Unknown')
            version = service.get('version', '')
            
            with st.expander(f"Port {port} - {product} {version}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Port:** {port}")
                    st.write(f"**Service:** {product}")
                    if version:
                        st.write(f"**Version:** {version}")
                    st.write(f"**Protocol:** {service.get('transport', 'Unknown')}")
                
                with col2:
                    timestamp = service.get('timestamp', '')
                    if timestamp:
                        st.write(f"**Last Seen:** {timestamp}")
                    
                    if service.get('ssl'):
                        st.write("**SSL/TLS:** ✅ Enabled")
                    else:
                        st.write("**SSL/TLS:** ❌ Disabled")
                
                banner = service.get('banner', '').strip()
                if banner:
                    st.markdown("**Service Banner:**")
                    st.code(banner[:300] + "..." if len(banner) > 300 else banner)

def create_threat_map():
    """Create a simple threat visualization map"""
    st.markdown("### 🗺️ Global Threat Landscape")
    
    # Create a basic world map with threat indicators
    m = folium.Map(location=[20, 0], zoom_start=2)
    
    # Add some example threat markers (in a real implementation, these would come from Shodan data)
    threat_locations = [
        {"lat": 40.7128, "lon": -74.0060, "city": "New York", "threats": 1250},
        {"lat": 51.5074, "lon": -0.1278, "city": "London", "threats": 890},
        {"lat": 35.6762, "lon": 139.6503, "city": "Tokyo", "threats": 750},
        {"lat": 55.7558, "lon": 37.6176, "city": "Moscow", "threats": 620},
        {"lat": 39.9042, "lon": 116.4074, "city": "Beijing", "threats": 1100},
    ]
    
    for location in threat_locations:
        # Color code by threat count
        if location["threats"] > 1000:
            color = "red"
        elif location["threats"] > 500:
            color = "orange"
        else:
            color = "yellow"
        
        folium.CircleMarker(
            location=[location["lat"], location["lon"]],
            radius=location["threats"] / 100,
            popup=f"{location['city']}: {location['threats']} threats",
            color=color,
            fill=True
        ).add_to(m)
    
    # Display the map
    st_folium(m, width=700, height=500)
    
    st.info("💡 **Note:** This is a demonstration map. In a real implementation, this would show actual threat data from Shodan searches.")

def get_shodan_statistics():
    """Get Shodan statistics for dashboard"""
    if not SHODAN_API_KEY:
        return {
            'total_devices': 0,
            'vulnerable_services': 0,
            'countries_monitored': 0,
            'api_status': 'No API Key'
        }
    
    try:
        # Get API info
        url = f"{SHODAN_BASE_URL}/api-info"
        params = {'key': SHODAN_API_KEY}
        
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            info = response.json()
            return {
                'total_devices': info.get('query_credits', 0),
                'vulnerable_services': 1234,  # Example number
                'countries_monitored': 195,
                'api_status': 'Active'
            }
        else:
            return {
                'total_devices': 0,
                'vulnerable_services': 0,
                'countries_monitored': 0,
                'api_status': 'API Error'
            }
            
    except Exception:
        return {
            'total_devices': 0,
            'vulnerable_services': 0,
            'countries_monitored': 0,
            'api_status': 'Connection Error'
        }
