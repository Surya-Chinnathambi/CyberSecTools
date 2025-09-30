from fastapi import APIRouter, Depends
import json
from datetime import datetime, timedelta
from typing import List, Dict

from routers.auth import verify_token
from utils.database import get_user_scans, get_db_connection

router = APIRouter()

@router.get("/stats")
async def get_dashboard_stats(user_data: dict = Depends(verify_token)):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT COUNT(*) FROM scan_results 
            WHERE user_id = ? AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
        """, (user_data['user_id'],))
        monthly_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scan_results WHERE user_id = ?", 
                      (user_data['user_id'],))
        total_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM reports WHERE user_id = ?", 
                      (user_data['user_id'],))
        total_reports = cursor.fetchone()[0]
    
    threat_level = calculate_threat_level(user_data['user_id'])
    
    return {
        "monthly_scans": monthly_scans,
        "total_scans": total_scans,
        "total_reports": total_reports,
        "threat_level": threat_level,
        "scan_limit": 999 if user_data['role'] == 'pro' else 5
    }

@router.get("/activity")
async def get_activity(user_data: dict = Depends(verify_token)):
    scans = get_user_scans(user_data['user_id'], limit=100)
    
    scan_activity = []
    for scan in scans:
        try:
            date = datetime.fromisoformat(scan['created_at'].replace('Z', '+00:00'))
            scan_activity.append({
                "date": date.date().isoformat(),
                "scan_type": scan['scan_type'],
                "target": scan['target']
            })
        except:
            continue
    
    return {"activity": scan_activity}

@router.get("/vulnerability-distribution")
async def get_vulnerability_distribution(user_data: dict = Depends(verify_token)):
    scans = get_user_scans(user_data['user_id'], limit=50)
    
    risk_counts = {'high': 0, 'medium': 0, 'low': 0}
    
    for scan in scans:
        try:
            results = json.loads(scan['results'])
            
            if scan['scan_type'] == 'web_scan':
                risk_summary = results.get('risk_summary', {})
                risk_counts['high'] += risk_summary.get('high', 0)
                risk_counts['medium'] += risk_summary.get('medium', 0)
                risk_counts['low'] += risk_summary.get('low', 0)
            elif scan['scan_type'] == 'port_scan':
                open_ports = len(results.get('open_ports', []))
                if open_ports > 10:
                    risk_counts['high'] += 1
                elif open_ports > 5:
                    risk_counts['medium'] += 1
                else:
                    risk_counts['low'] += 1
        except:
            continue
    
    return {"distribution": risk_counts}

def calculate_threat_level(user_id: int):
    scans = get_user_scans(user_id, limit=20)
    
    if not scans:
        return "LOW"
    
    total_risk_score = 0
    scan_count = 0
    
    for scan in scans:
        try:
            results = json.loads(scan['results'])
            
            if scan['scan_type'] == 'web_scan':
                risk_summary = results.get('risk_summary', {})
                score = (risk_summary.get('high', 0) * 3 + 
                        risk_summary.get('medium', 0) * 2 + 
                        risk_summary.get('low', 0) * 1)
                total_risk_score += score
                scan_count += 1
            elif scan['scan_type'] == 'port_scan':
                open_ports = len(results.get('open_ports', []))
                if open_ports > 15:
                    total_risk_score += 3
                elif open_ports > 8:
                    total_risk_score += 2
                else:
                    total_risk_score += 1
                scan_count += 1
        except:
            continue
    
    if scan_count == 0:
        return "LOW"
    
    avg_risk = total_risk_score / scan_count
    
    if avg_risk >= 8:
        return "CRITICAL"
    elif avg_risk >= 5:
        return "HIGH"
    elif avg_risk >= 2:
        return "MEDIUM"
    else:
        return "LOW"
