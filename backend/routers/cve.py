from fastapi import APIRouter, HTTPException, Depends
import requests
from typing import List, Optional

from routers.auth import verify_token

router = APIRouter()

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

@router.get("/search")
async def search_cves(
    keyword: str,
    limit: int = 20,
    user_data: dict = Depends(verify_token)
):
    try:
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': limit
        }
        
        response = requests.get(NVD_BASE_URL, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = []
        
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id', 'Unknown')
            
            descriptions = cve.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            metrics = cve.get('metrics', {})
            cvss_score = 0.0
            
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]
                    if 'cvssData' in metric:
                        cvss_score = metric['cvssData'].get('baseScore', 0.0)
                        break
            
            vulnerabilities.append({
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': get_severity_from_score(cvss_score),
                'published_date': cve.get('published', ''),
                'modified_date': cve.get('lastModified', '')
            })
        
        return {"cves": vulnerabilities}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CVE search failed: {str(e)}")

@router.get("/details/{cve_id}")
async def get_cve_details(
    cve_id: str,
    user_data: dict = Depends(verify_token)
):
    try:
        params = {'cveId': cve_id}
        response = requests.get(NVD_BASE_URL, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        if not data.get('vulnerabilities'):
            raise HTTPException(status_code=404, detail="CVE not found")
        
        item = data['vulnerabilities'][0]
        cve = item.get('cve', {})
        
        descriptions = cve.get('descriptions', [])
        description = descriptions[0].get('value', '') if descriptions else ''
        
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
        
        references = []
        for ref in cve.get('references', []):
            references.append({
                'url': ref.get('url', ''),
                'source': ref.get('source', ''),
                'tags': ref.get('tags', [])
            })
        
        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'severity': get_severity_from_score(cvss_score),
            'published_date': cve.get('published', ''),
            'modified_date': cve.get('lastModified', ''),
            'references': references
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching CVE details: {str(e)}")

def get_severity_from_score(score: float) -> str:
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
