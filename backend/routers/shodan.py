from fastapi import APIRouter, HTTPException, Depends
import requests
import os

from routers.auth import verify_token

router = APIRouter()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SHODAN_BASE_URL = "https://api.shodan.io"

@router.get("/search")
async def search_shodan(
    query: str,
    limit: int = 100,
    user_data: dict = Depends(verify_token)
):
    if not SHODAN_API_KEY:
        raise HTTPException(status_code=503, detail="Shodan API key not configured")
    
    try:
        url = f"{SHODAN_BASE_URL}/shodan/host/search"
        params = {
            'key': SHODAN_API_KEY,
            'query': query,
            'limit': limit
        }
        
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        return response.json()
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Shodan search failed: {str(e)}")

@router.get("/host/{ip}")
async def get_host_info(
    ip: str,
    user_data: dict = Depends(verify_token)
):
    if not SHODAN_API_KEY:
        raise HTTPException(status_code=503, detail="Shodan API key not configured")
    
    try:
        url = f"{SHODAN_BASE_URL}/shodan/host/{ip}"
        params = {'key': SHODAN_API_KEY}
        
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        return response.json()
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Host lookup failed: {str(e)}")

@router.get("/api-info")
async def get_api_info(user_data: dict = Depends(verify_token)):
    if not SHODAN_API_KEY:
        return {"status": "not_configured"}
    
    try:
        url = f"{SHODAN_BASE_URL}/api-info"
        params = {'key': SHODAN_API_KEY}
        
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        
        return response.json()
    
    except Exception as e:
        return {"status": "error", "message": str(e)}
