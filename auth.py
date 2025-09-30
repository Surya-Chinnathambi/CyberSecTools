import streamlit as st
import sqlite3
import jwt
import datetime
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from database import get_db_connection

# Secure session secret - required in production
SESSION_SECRET = os.getenv("SESSION_SECRET")
if not SESSION_SECRET:
    if os.getenv("DEV_MODE", "false").lower() == "true":
        SESSION_SECRET = "dev_secret_key_not_for_production"
    else:
        raise ValueError("SESSION_SECRET environment variable is required for production")

# Initialize secure password hasher
ph = PasswordHasher()

def init_auth():
    """Initialize authentication system"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = {}

def hash_password(password):
    """Hash password using Argon2"""
    return ph.hash(password)

def verify_password(password, hashed):
    """Verify password against Argon2 hash"""
    try:
        ph.verify(hashed, password)
        return True
    except VerifyMismatchError:
        return False

def create_jwt_token(user_id, username, role):
    """Create JWT token for user session"""
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    token = jwt.encode(payload, SESSION_SECRET, algorithm='HS256')
    return token

def verify_jwt_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, SESSION_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def register_user(username, email, password):
    """Register new user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
    if cursor.fetchone():
        conn.close()
        return False, "User already exists"
    
    # Create user
    hashed_password = hash_password(password)
    cursor.execute("""
        INSERT INTO users (username, email, password_hash, role, created_at)
        VALUES (?, ?, ?, 'free', ?)
    """, (username, email, hashed_password, datetime.datetime.now()))
    
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return True, user_id

def authenticate_user(username, password):
    """Authenticate user login"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, username, email, role, password_hash FROM users 
        WHERE username = ?
    """, (username,))
    
    user = cursor.fetchone()
    conn.close()
    
    if user and verify_password(password, user[4]):
        return True, {
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[3]
        }
    return False, None

def check_authentication():
    """Check if user is authenticated and show login/register if not"""
    if st.session_state.get('authenticated', False):
        return True
    
    # Login/Register tabs
    tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
    
    with tab1:
        st.subheader("Login to CyberSec AI Platform")
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("🚀 Login")
            
            if submitted:
                if username and password:
                    success, user_info = authenticate_user(username, password)
                    if success and user_info:
                        st.session_state.authenticated = True
                        st.session_state.user_info = user_info
                        st.session_state.jwt_token = create_jwt_token(
                            user_info['id'], user_info['username'], user_info['role']
                        )
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("Invalid credentials")
                else:
                    st.error("Please fill in all fields")
    
    with tab2:
        st.subheader("Create New Account")
        with st.form("register_form"):
            new_username = st.text_input("Choose Username")
            new_email = st.text_input("Email Address")
            new_password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            submitted = st.form_submit_button("🎯 Create Account")
            
            if submitted:
                if new_username and new_email and new_password and confirm_password:
                    if new_password != confirm_password:
                        st.error("Passwords don't match")
                    elif len(new_password) < 6:
                        st.error("Password must be at least 6 characters")
                    else:
                        success, result = register_user(new_username, new_email, new_password)
                        if success:
                            st.success("Account created successfully! Please login.")
                        else:
                            st.error(result)
                else:
                    st.error("Please fill in all fields")
    
    return False

def get_user_usage():
    """Get user's current usage statistics"""
    user_info = st.session_state.get('user_info', {})
    if not user_info:
        return {'scans': 0, 'limit': 5}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get scan count for current month
    cursor.execute("""
        SELECT COUNT(*) FROM scan_results 
        WHERE user_id = ? AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
    """, (user_info['id'],))
    
    scan_count = cursor.fetchone()[0]
    conn.close()
    
    # Set limits based on role
    limit = 999 if user_info.get('role') == 'pro' else 5
    
    return {'scans': scan_count, 'limit': limit}

def check_scan_limit():
    """Check if user has reached scan limit"""
    usage = get_user_usage()
    st.session_state.usage = usage
    
    if usage['scans'] >= usage['limit']:
        st.error("🚫 Scan limit reached! Upgrade to Pro for unlimited scans.")
        return False
    return True
