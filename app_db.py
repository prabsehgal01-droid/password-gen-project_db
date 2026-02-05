import streamlit as st
import secrets
import string
import hashlib
import time
import sqlite3

# --- CONFIGURATION & UTILS ---
st.set_page_config(page_title="SecurePass Pro DB", page_icon="💾", layout="centered")

# --- DATABASE MANAGEMENT (SQLite) ---
def init_db():
    """Initializes the SQLite database and creates tables if they don't exist."""
    conn = sqlite3.connect('my_database.db')
    c = conn.cursor()
    
    # Table 1: Users (For Login)
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Table 2: Saved Passwords (For the Vault)
    c.execute('''
        CREATE TABLE IF NOT EXISTS saved_passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            site_name TEXT,
            generated_password TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(username) REFERENCES users(username)
        )
    ''')
    conn.commit()
    conn.close()

# Run initialization once
init_db()

# --- DB HELPER FUNCTIONS ---
def add_user(username, password_hash):
    try:
        conn = sqlite3.connect('my_database.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False # Username already exists

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
    c.execute('SELECT site_name, generated_password, timestamp FROM saved_passwords WHERE username = ? ORDER BY id DESC', (username,))
    data = c.fetchall()
    conn.close()
    return data

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

# --- SESSION STATE ---
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'current_user' not in st.session_state:
    st.session_state['current_user'] = None

# --- UI: LOGIN PAGE ---
def login_page():
    st.title("💾 SecurePass Pro | Login")
    
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        
        if st.button("Login"):
            hashed_pw = hash_password(password)
            if verify_login(username, hashed_pw):
                st.session_state['logged_in'] = True
                st.session_state['current_user'] = username
                st.success("Login Successful!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Invalid Username or Password.")

    with tab2:
        new_user = st.text_input("New Username", key="signup_user")
        new_pass = st.text_input("New Password", type="password", key="signup_pass")
        
        if st.button("Create Account"):
            if len(new_pass) < 4:
                st.warning("Password must be at least 4 characters.")
            else:
                success = add_user(new_user, hash_password(new_pass))
                if success:
                    st.success("Account created! Please login.")
                else:
                    st.error("Username already exists.")

# --- UI: MAIN APP ---
def main_app():
    # --- SIDEBAR ---
    st.sidebar.title(f"👤 {st.session_state['current_user']}")
    
    # ... your existing Logout button is here ...
    if st.sidebar.button("Logout"):
        st.session_state['logged_in'] = False
        st.rerun()
    
    st.sidebar.markdown("---")
    
    # ⬇️ ADD THIS NEW CODE HERE ⬇️
    st.sidebar.subheader("Admin Tools")
    
    # Read the database file as bytes
    try:
        with open("my_database.db", "rb") as fp:
            btn = st.sidebar.download_button(
                label="📥 Download Database File",
                data=fp,
                file_name="my_database.db",
                mime="application/octet-stream",
                help="Download the actual SQL file to your computer."
            )
    except FileNotFoundError:
        st.sidebar.warning("Database not created yet.")
    # Show Database History
    st.markdown("---")
    st.subheader("📂 Your Saved Passwords (From Database)")
    
    history = get_user_history(st.session_state['current_user'])
    
    if history:
        # Display as a clean table
        # history format: [(site, pass, time), (site, pass, time)...]
        for item in history:
            site, pwd, tm = item
            with st.expander(f"{site} - {tm}"):
                st.code(pwd, language='')
    else:
        st.info("No passwords saved in database yet.")

# --- ROUTING ---
if st.session_state['logged_in']:
    main_app()
else:
    login_page()
