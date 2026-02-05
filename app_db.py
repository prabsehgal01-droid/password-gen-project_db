import streamlit as st
import secrets
import string
import hashlib
import time
import sqlite3
import math

# --- CONFIGURATION ---
st.set_page_config(page_title="SecurePass Pro DB", page_icon="💾", layout="centered")

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('my_database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS saved_passwords 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, 
                  site_name TEXT, generated_password TEXT, 
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(username) REFERENCES users(username))''')
    conn.commit()
    conn.close()

# Initialize DB on app start
init_db()

# --- DATABASE FUNCTIONS ---
def add_user(username, password_hash):
    try:
        conn = sqlite3.connect('my_database.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False

def verify_login(username, password_hash):
    conn = sqlite3.connect('my_database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
    user = c.fetchone()
    conn.close()
    return user is not None

def save_pass_to_db(username, site, password):
    conn = sqlite3.connect('my_database.db')
    c = conn.cursor()
    c.execute('INSERT INTO saved_passwords (username, site_name, generated_password) VALUES (?, ?, ?)', 
              (username, site, password))
    conn.commit()
    conn.close()

def get_user_history(username):
    conn = sqlite3.connect('my_database.db')
    c = conn.cursor()
    c.execute('SELECT id, site_name, generated_password, timestamp FROM saved_passwords WHERE username = ? ORDER BY id DESC', (username,))
    data = c.fetchall()
    conn.close()
    return data

def delete_password(pass_id):
    conn = sqlite3.connect('my_database.db')
    c = conn.cursor()
    c.execute('DELETE FROM saved_passwords WHERE id = ?', (pass_id,))
    conn.commit()
    conn.close()

# --- CRACK TIME ESTIMATOR ---
def calculate_crack_time(password):
    pool_size = 0
    if any(c.islower() for c in password): pool_size += 26
    if any(c.isupper() for c in password): pool_size += 26
    if any(c.isdigit() for c in password): pool_size += 10
    if any(c in string.punctuation for c in password): pool_size += 32
    
    entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0
    guesses_per_sec = 10_000_000_000 
    seconds = (2 ** entropy) / guesses_per_sec
    
    if seconds < 60: return "Instantly 😱", "red"
    elif seconds < 3600: return "Few Minutes ⚠️", "orange"
    elif seconds < 86400: return "Few Hours ⚠️", "orange"
    elif seconds < 31536000: return f"{int(seconds/86400)} Days 🛡️", "yellow"
    else: return "Centuries (Unbreakable) 💎", "green"

# --- CORE LOGIC ---
def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def generate_password(length, use_digits, use_symbols):
    characters = string.ascii_letters
    if use_digits: characters += string.digits
    if use_symbols: characters += string.punctuation
    
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        if use_digits and not any(c.isdigit() for c in password): continue
        if use_symbols and not any(c in string.punctuation for c in password): continue
        return password

if 'logged_in' not in st.session_state: st.session_state['logged_in'] = False
if 'current_user' not in st.session_state: st.session_state['current_user'] = None

# --- UI: LOGIN ---
def login_page():
    st.title("💾 SecurePass Pro | Login")
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        u = st.text_input("Username", key="login_user")
        p = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            if verify_login(u, hash_password(p)):
                st.session_state['logged_in'] = True
                st.session_state['current_user'] = u
                st.rerun()
            else:
                st.error("Invalid Credentials")

    with tab2:
        nu = st.text_input("New Username", key="signup_user")
        np = st.text_input("New Password", type="password", key="signup_pass")
        if st.button("Create Account"):
