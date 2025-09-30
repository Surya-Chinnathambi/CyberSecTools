import sqlite3
import os
from datetime import datetime
from contextlib import contextmanager

DB_PATH = "cybersec_platform.db"

@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_database():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'free',
                stripe_customer_id TEXT,
                subscription_id TEXT,
                subscription_updated_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
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
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shodan_cache (
                ip_address TEXT PRIMARY KEY,
                data TEXT,
                cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
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

def save_scan_result(user_id: int, scan_type: str, target: str, results: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_results (user_id, scan_type, target, status, results, completed_at)
            VALUES (?, ?, ?, 'completed', ?, ?)
        """, (user_id, scan_type, target, results, datetime.now()))
        conn.commit()
        return cursor.lastrowid

def get_user_scans(user_id: int, limit: int = 10):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM scan_results 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ?
        """, (user_id, limit))
        scans = cursor.fetchall()
        return [dict(scan) for scan in scans]
