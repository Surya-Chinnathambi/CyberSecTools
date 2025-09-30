from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
import json
from typing import List, Dict

from models.scan import PortScanRequest, WebScanRequest, ScanResponse
from routers.auth import verify_token
from services.port_scanner_service import perform_port_scan
from services.web_scanner_service import perform_web_scan
from utils.database import save_scan_result, get_user_scans, get_db_connection

router = APIRouter()

@router.post("/port", response_model=dict)
async def scan_ports(
    request: PortScanRequest,
    user_data: dict = Depends(verify_token)
):
    if not check_scan_limit(user_data['user_id'], user_data['role']):
        raise HTTPException(status_code=403, detail="Scan limit reached")
    
    try:
        results = perform_port_scan(request.host, request.ports, request.scan_type)
        
        scan_id = save_scan_result(
            user_data['user_id'],
            'port_scan',
            request.host,
            json.dumps(results)
        )
        
        return {
            "success": True,
            "scan_id": scan_id,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/web", response_model=dict)
async def scan_web(
    request: WebScanRequest,
    user_data: dict = Depends(verify_token)
):
    if not check_scan_limit(user_data['user_id'], user_data['role']):
        raise HTTPException(status_code=403, detail="Scan limit reached")
    
    try:
        results = perform_web_scan(request.url, request.options)
        
        scan_id = save_scan_result(
            user_data['user_id'],
            'web_scan',
            request.url,
            json.dumps(results)
        )
        
        return {
            "success": True,
            "scan_id": scan_id,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/history", response_model=List[dict])
async def get_scan_history(
    limit: int = 10,
    user_data: dict = Depends(verify_token)
):
    scans = get_user_scans(user_data['user_id'], limit)
    
    for scan in scans:
        if scan.get('results'):
            try:
                scan['results'] = json.loads(scan['results'])
            except:
                pass
    
    return scans

@router.get("/result/{scan_id}", response_model=dict)
async def get_scan_result(
    scan_id: int,
    user_data: dict = Depends(verify_token)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM scan_results 
            WHERE id = ? AND user_id = ?
        """, (scan_id, user_data['user_id']))
        
        scan = cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan_dict = dict(scan)
        if scan_dict.get('results'):
            try:
                scan_dict['results'] = json.loads(scan_dict['results'])
            except:
                pass
        
        return scan_dict

def check_scan_limit(user_id: int, role: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM scan_results 
            WHERE user_id = ? AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
        """, (user_id,))
        
        monthly_scans = cursor.fetchone()[0]
        limit = 999 if role == 'pro' else 5
        
        return monthly_scans < limit
