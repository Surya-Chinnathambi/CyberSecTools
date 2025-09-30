import sqlite3
import os
import datetime

DB_PATH = "cybersec_platform.db"

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize database with required tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'free',
            stripe_customer_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Scan results table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            results TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    # CVE data cache table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            severity TEXT,
            published_date TEXT,
            modified_date TEXT,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Shodan data cache table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS shodan_cache (
            ip_address TEXT PRIMARY KEY,
            data TEXT,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Exploit database table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exploits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exploit_id TEXT UNIQUE,
            title TEXT,
            description TEXT,
            type TEXT,
            platform TEXT,
            date_published TEXT,
            author TEXT,
            verified BOOLEAN DEFAULT FALSE
        )
    """)
    
    # Reports table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            report_name TEXT,
            report_type TEXT,
            file_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    conn.commit()
    conn.close()

def save_scan_result(user_id, scan_type, target, results):
    """Save scan result to database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO scan_results (user_id, scan_type, target, status, results, completed_at)
        VALUES (?, ?, ?, 'completed', ?, ?)
    """, (user_id, scan_type, target, results, datetime.datetime.now()))
    
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return scan_id

def get_user_scans(user_id, limit=10):
    """Get user's recent scans"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM scan_results 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT ?
    """, (user_id, limit))
    
    scans = cursor.fetchall()
    conn.close()
    
    return [dict(scan) for scan in scans]

def cache_cve_data(cve_id, description, cvss_score, severity, published_date, modified_date):
    """Cache CVE data"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT OR REPLACE INTO cve_cache 
        (cve_id, description, cvss_score, severity, published_date, modified_date)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (cve_id, description, cvss_score, severity, published_date, modified_date))
    
    conn.commit()
    conn.close()

def get_cached_cve_data(cve_id):
    """Get cached CVE data"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM cve_cache WHERE cve_id = ?", (cve_id,))
    result = cursor.fetchone()
    conn.close()
    
    return dict(result) if result else None
