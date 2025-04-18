import os
import json
import time
import base64
import hashlib
from cryptography.fernet import Fernet
import streamlit as st

# === Constants ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60  # seconds

# === Utility Functions ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def derive_key(passkey):
    key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return base64.urlsafe_b64encode(key)

def encrypt_text(text, passkey):
    cipher = Fernet(derive_key(passkey))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, passkey):
    try:
        cipher = Fernet(derive_key(passkey))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# === Session State Initialization ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === Load Stored Data ===
stored_data = load_data()

# === UI ===
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# === Home Page ===
if choice == "Home":
    st.subheader("Welcome to the Encrypted Data Vault 🛡️")
    st.markdown("""
    - 🔐 Store and retrieve encrypted data using a passphrase
    - 🧠 Three failed login attempts lock you out temporarily
    - 🧾 No external database, purely file-based
    """)

# === Register ===
elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ Registered successfully!")
        else:
            st.error("❗ Both fields are required.")

# === Login ===
elif choice == "Login":
    st.subheader("🔐 Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⛔ Too many failed attempts. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            attempts_left = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts left: {attempts_left}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("⛔ Locked for 60 seconds.")

# === Store Data ===
elif choice == "Store Data":
    if st.session_state.authenticated_user:
        st.subheader("📥 Store Encrypted Data")
        data = st.text_area("Enter Data to Encrypt")
        passkey = st.text_input("Encryption Passphrase", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved.")
            else:
                st.error("❗ All fields are required to filled.")
    else:
        st.warning("🔐 Please login to access this section.")

# === Retrieve Data ===
elif choice == "Retrieve Data":
    if st.session_state.authenticated_user:
        st.subheader("📤 Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("📭 No data found.")
        else:
            st.write("🗂️ Encrypted Entries:")
            for i, item in enumerate(user_data):
                st.code(item)

            encrypted_input = st.text_area("Paste Encrypted Text")
            passkey = st.text_input("Decryption Passphrase", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"🔓 Decrypted Text: {result}")
                else:
                    st.error("❌ Incorrect passphrase or invalid data.")
    else:
        st.warning("🔐 Please login to access this section.")
