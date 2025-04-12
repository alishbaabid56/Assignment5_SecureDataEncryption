# import streamlit as st
# import hashlib
# import json
# import os
# import time
# import csv
# from cryptography.fernet import Fernet
# import base64

# # --- Load or Generate Encryption Key ---
# def load_key():
#     if os.path.exists("secret.key"):
#         with open("secret.key", "rb") as key_file:
#             return key_file.read()
#     else:
#         key = Fernet.generate_key()
#         with open("secret.key", "wb") as key_file:
#             key_file.write(key)
#         return key

# KEY = load_key()
# cipher = Fernet(KEY)
# DATA_FILE = 'secure_data.json'
# USERS_FILE = 'users.json'
# LOCKOUT_TIME = 60

# # --- Load Data ---
# def load_json_file(file):
#     if os.path.exists(file):
#         with open(file, 'r') as f:
#             return json.load(f)
#     return {}

# stored_data = load_json_file(DATA_FILE)
# users = load_json_file(USERS_FILE)
# failed_attempts = {}
# lockout_start = {}

# # --- Save Data ---
# def save_json(file, data):
#     with open(file, 'w') as f:
#         json.dump(data, f, indent=4)

# # --- PBKDF2 Secure Hashing ---
# def hash_passkey(passkey, salt="static_salt"):
#     return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000).hex()

# # --- Encrypt and Decrypt ---
# def encrypt_data(text):
#     return cipher.encrypt(text.encode()).decode()

# def decrypt_data(encrypted_text):
#     return cipher.decrypt(encrypted_text.encode()).decode()

# # --- Lockout Check ---
# def is_locked_out(username):
#     if username in lockout_start:
#         elapsed = time.time() - lockout_start[username]
#         if elapsed < LOCKOUT_TIME:
#             return True, int(LOCKOUT_TIME - elapsed)
#         else:
#             del lockout_start[username]
#             failed_attempts[username] = 0
#             return False, 0
#     return False, 0

# # --- UI Setup ---
# st.set_page_config(page_title="🔐 Secure Data App", layout="centered")
# st.title("🔐 Secure Data Encryption System")

# menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Export"]
# choice = st.sidebar.selectbox("Navigation", menu)

# # --- Home Page ---
# if choice == "Home":
#     st.markdown("""
#     ### 🔐 Welcome to Secure Data Vault
#     - End-to-end data encryption with Fernet
#     - PBKDF2 passkey hashing
#     - Multi-user login
#     - Export your data to `.csv` or `.txt`
#     - Ready to deploy to **Streamlit Cloud**, **Hugging Face**, or **Render**
#     """)

# # --- Register Page ---
# elif choice == "Register":
#     st.header("👤 Register")
#     new_user = st.text_input("Choose a Username")
#     new_pass = st.text_input("Choose a Passkey", type="password")

#     if st.button("Register"):
#         if new_user in users:
#             st.warning("❗ Username already exists.")
#         else:
#             users[new_user] = hash_passkey(new_pass)
#             save_json(USERS_FILE, users)
#             st.success("✅ Registered successfully!")

# # --- Login Page ---
# elif choice == "Login":
#     st.header("🔐 User Login")
#     user = st.text_input("Username")
#     user_pass = st.text_input("Passkey", type="password")

#     if st.button("Login"):
#         if user in users and users[user] == hash_passkey(user_pass):
#             st.success(f"✅ Welcome, {user}!")
#             st.session_state["user"] = user
#         else:
#             st.error("❌ Invalid login")

# # --- Store Data Page ---
# elif choice == "Store Data":
#     if "user" not in st.session_state:
#         st.warning("🔒 Please log in first!")
#     else:
#         st.header("📂 Store Data")
#         user = st.session_state["user"]
#         data_to_store = st.text_area("Enter Data to Encrypt:")
#         passkey = st.text_input("Re-enter Passkey", type="password")

#         if st.button("Encrypt & Save"):
#             if hash_passkey(passkey) == users[user]:
#                 encrypted = encrypt_data(data_to_store)
#                 timestamp = time.ctime()
#                 stored_data[user] = {
#                     "data": encrypted,
#                     "last_modified": timestamp,
#                     "access_log": []
#                 }
#                 save_json(DATA_FILE, stored_data)
#                 st.success("✅ Data encrypted and stored.")
#             else:
#                 st.error("❌ Incorrect passkey!")

# # --- Retrieve Data Page ---
# elif choice == "Retrieve Data":
#     if "user" not in st.session_state:
#         st.warning("🔒 Please log in first!")
#     else:
#         st.header("🔍 Retrieve Data")
#         user = st.session_state["user"]
#         passkey = st.text_input("Re-enter Passkey", type="password")

#         locked, time_left = is_locked_out(user)
#         if locked:
#             st.warning(f"⏳ Too many failed attempts. Wait {time_left}s.")
#         elif st.button("Decrypt"):
#             if user in stored_data:
#                 if hash_passkey(passkey) == users[user]:
#                     decrypted = decrypt_data(stored_data[user]["data"])
#                     access_time = time.ctime()
#                     stored_data[user]["access_log"].append(access_time)
#                     save_json(DATA_FILE, stored_data)
#                     st.success("✅ Data Decrypted")
#                     st.code(decrypted)
#                 else:
#                     failed_attempts[user] = failed_attempts.get(user, 0) + 1
#                     st.error(f"❌ Wrong passkey! ({failed_attempts[user]}/3)")
#                     if failed_attempts[user] >= 3:
#                         lockout_start[user] = time.time()
#             else:
#                 st.error("❗ No data found!")

# # --- Export Page ---
# elif choice == "Export":
#     if "user" not in st.session_state:
#         st.warning("🔒 Please log in first!")
#     else:
#         st.header("📤 Export Your Data")
#         user = st.session_state["user"]

#         if user in stored_data:
#             decrypted = decrypt_data(stored_data[user]["data"])
#             timestamp = stored_data[user]["last_modified"]
#             access_log = stored_data[user]["access_log"]

#             if st.button("Export to TXT"):
#                 content = f"Data for {user}\nTimestamp: {timestamp}\n\n{decrypted}\n\nAccess Log:\n" + "\n".join(access_log)
#                 st.download_button("📄 Download TXT", content, file_name=f"{user}_data.txt")

#             if st.button("Export to CSV"):
#                 csv_filename = f"{user}_data.csv"
#                 csv_data = [["Username", "Timestamp", "Decrypted Data", "Access Count"],
#                             [user, timestamp, decrypted, len(access_log)]]

#                 with open(csv_filename, mode='w', newline='') as file:
#                     writer = csv.writer(file)
#                     writer.writerows(csv_data)

#                 with open(csv_filename, "rb") as file:
#                     btn = st.download_button("📑 Download CSV", file, file_name=csv_filename)
#         else:
#             st.info("No data found to export.")

import streamlit as st
import hashlib
import json
import os
import time
import csv
from cryptography.fernet import Fernet
import base64
import re
from datetime import datetime

# --- Configuration ---
st.set_page_config(
    page_title="🔐 Secure Data Vault",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="expanded"
)

# --- Load or Generate Encryption Key ---
def load_key():
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key

KEY = load_key()
cipher = Fernet(KEY)
DATA_FILE = 'secure_data.json'
USERS_FILE = 'users.json'
LOCKOUT_TIME = 60
MAX_ATTEMPTS = 3

# --- Load Data ---
def load_json_file(file):
    if os.path.exists(file):
        with open(file, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

stored_data = load_json_file(DATA_FILE)
users = load_json_file(USERS_FILE)
failed_attempts = {}
lockout_start = {}

# --- Save Data ---
def save_json(file, data):
    try:
        with open(file, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        st.error(f"Error saving data: {str(e)}")

# --- PBKDF2 Secure Hashing ---
def hash_passkey(passkey, salt="static_salt"):
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000).hex()

# --- Encrypt and Decrypt ---
def encrypt_data(text):
    try:
        return cipher.encrypt(text.encode()).decode()
    except Exception as e:
        st.error(f"Encryption failed: {str(e)}")
        return None

def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        st.error(f"Decryption failed: {str(e)}")
        return None

# --- Input Validation ---
def validate_username(username):
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters long"
    if not re.match("^[a-zA-Z0-9_]+$", username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, ""

def validate_password(password):
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search("[A-Z]", password) or not re.search("[0-9]", password):
        return False, "Password must contain at least one uppercase letter and one number"
    return True, ""

# --- Lockout Check ---
def is_locked_out(username):
    if username in lockout_start:
        elapsed = time.time() - lockout_start[username]
        if elapsed < LOCKOUT_TIME:
            return True, int(LOCKOUT_TIME - elapsed)
        else:
            del lockout_start[username]
            failed_attempts[username] = 0
            return False, 0
    return False, 0

# --- UI Styling ---
st.markdown("""
    <style>
    .main {padding: 2rem;}
    .stButton>button {width: 100%; background-color: #1E88E5; color: white;}
    .stTextInput>div>input {border-radius: 5px;}
    .sidebar .sidebar-content {background-color: #f8f9fa;}
    </style>
""", unsafe_allow_html=True)

# --- Header ---
st.title("🔐 Secure Data Vault")
st.markdown("A professional end-to-end encrypted data management system")

# --- Sidebar Navigation ---
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Export"]
choice = st.sidebar.selectbox("Navigation", menu, format_func=lambda x: f"📌 {x}")

# --- Home Page ---
if choice == "Home":
    st.header("Welcome to Secure Data Vault")
    st.markdown("""
    ### 🔒 Professional Features
    - **End-to-End Encryption**: Using Fernet (AES-128)
    - **Secure Authentication**: PBKDF2 passkey hashing
    - **Multi-User Support**: Individual encrypted storage
    - **Data Export**: CSV and TXT formats
    - **Access Logging**: Track data retrieval
  
    
    Get started by registering or logging in from the sidebar.
    """)
    st.info("All data is encrypted at rest and in transit")

# --- Register Page ---
elif choice == "Register":
    st.header("👤 Create Account")
    with st.form("register_form"):
        new_user = st.text_input("Username", help="Use letters, numbers, and underscores")
        new_pass = st.text_input("Password", type="password", help="Minimum 8 characters with uppercase and number")
        confirm_pass = st.text_input("Confirm Password", type="password")
        submit = st.form_submit_button("Register")

        if submit:
            valid_user, user_msg = validate_username(new_user)
            valid_pass, pass_msg = validate_password(new_pass)

            if not valid_user:
                st.error(user_msg)
            elif not valid_pass:
                st.error(pass_msg)
            elif new_pass != confirm_pass:
                st.error("Passwords do not match")
            elif new_user in users:
                st.warning("Username already exists")
            else:
                # Encrypt user data during registration
                encrypted_user_data = encrypt_data(json.dumps({"username": new_user, "created": datetime.now().isoformat()}))
                users[new_user] = {
                    "passkey": hash_passkey(new_pass),
                    "encrypted_data": encrypted_user_data
                }
                save_json(USERS_FILE, users)
                st.success(f"Account created successfully for {new_user}! Please login.")
                st.balloons()

# --- Login Page ---
elif choice == "Login":
    st.header("🔐 Sign In")
    with st.form("login_form"):
        user = st.text_input("Username")
        user_pass = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")

        if submit:
            locked, time_left = is_locked_out(user)
            if locked:
                st.error(f"Account locked. Try again in {time_left} seconds")
            elif user in users and users[user]["passkey"] == hash_passkey(user_pass):
                st.session_state["user"] = user
                failed_attempts[user] = 0
                st.success(f"Welcome back, {user}!")
                st.rerun()
            else:
                failed_attempts[user] = failed_attempts.get(user, 0) + 1
                attempts_left = MAX_ATTEMPTS - failed_attempts.get(user, 0)
                st.error(f"Invalid credentials. {attempts_left} attempts remaining")
                if failed_attempts[user] >= MAX_ATTEMPTS:
                    lockout_start[user] = time.time()

# --- Store Data Page ---
elif choice == "Store Data":
    if "user" not in st.session_state:
        st.error("🔒 Please login first")
    else:
        st.header("📂 Store Secure Data")
        user = st.session_state["user"]
        with st.form("store_form"):
            data_to_store = st.text_area("Data to Encrypt:", help="Enter sensitive information to secure")
            passkey = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Encrypt & Store")

            if submit:
                if not data_to_store:
                    st.error("Please enter data to encrypt")
                elif hash_passkey(passkey) != users[user]["passkey"]:
                    st.error("Incorrect password")
                else:
                    encrypted = encrypt_data(data_to_store)
                    if encrypted:
                        timestamp = datetime.now().isoformat()
                        stored_data[user] = {
                            "data": encrypted,
                            "last_modified": timestamp,
                            "access_log": stored_data.get(user, {}).get("access_log", [])
                        }
                        save_json(DATA_FILE, stored_data)
                        st.success("Data encrypted and stored successfully")
                        st.balloons()

# --- Retrieve Data Page ---
elif choice == "Retrieve Data":
    if "user" not in st.session_state:
        st.error("🔒 Please login first")
    else:
        st.header("🔍 Access Your Data")
        user = st.session_state["user"]
        with st.form("retrieve_form"):
            passkey = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Decrypt Data")

            locked, time_left = is_locked_out(user)
            if locked:
                st.error(f"Account locked. Try again in {time_left} seconds")
            elif submit:
                if user in stored_data:
                    if hash_passkey(passkey) == users[user]["passkey"]:
                        decrypted = decrypt_data(stored_data[user]["data"])
                        if decrypted:
                            access_time = datetime.now().isoformat()
                            stored_data[user]["access_log"].append(access_time)
                            save_json(DATA_FILE, stored_data)
                            st.success("Data retrieved successfully")
                            st.markdown("### Your Data:")
                            st.code(decrypted, language="text")
                            st.markdown(f"**Last Modified:** {stored_data[user]['last_modified']}")
                            st.markdown(f"**Access Count:** {len(stored_data[user]['access_log'])}")
                    else:
                        failed_attempts[user] = failed_attempts.get(user, 0) + 1
                        attempts_left = MAX_ATTEMPTS - failed_attempts.get(user, 0)
                        st.error(f"Incorrect password. {attempts_left} attempts remaining")
                        if failed_attempts[user] >= MAX_ATTEMPTS:
                            lockout_start[user] = time.time()
                else:
                    st.info("No data stored yet")

# --- Export Page ---
elif choice == "Export":
    if "user" not in st.session_state:
        st.error("🔒 Please login first")
    else:
        st.header("📤 Export Data")
        user = st.session_state["user"]

        if user in stored_data:
            decrypted = decrypt_data(stored_data[user]["data"])
            if decrypted:
                timestamp = stored_data[user]["last_modified"]
                access_log = stored_data[user]["access_log"]

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Export to TXT", use_container_width=True):
                        content = (
                            f"Secure Data Vault Export\n"
                            f"Username: {user}\n"
                            f"Last Modified: {timestamp}\n\n"
                            f"Data:\n{decrypted}\n\n"
                            f"Access Log ({len(access_log)} entries):\n" + "\n".join(access_log)
                        )
                        st.download_button(
                            "Download TXT",
                            content,
                            file_name=f"vault_{user}_{timestamp[:10]}.txt",
                            use_container_width=True
                        )

                with col2:
                    if st.button("Export to CSV", use_container_width=True):
                        csv_filename = f"vault_{user}_{timestamp[:10]}.csv"
                        csv_data = [
                            ["Username", "Timestamp", "Decrypted Data", "Access Count"],
                            [user, timestamp, decrypted, len(access_log)]
                        ]
                        with open(csv_filename, mode='w', newline='') as file:
                            writer = csv.writer(file)
                            writer.writerows(csv_data)

                        with open(csv_filename, "rb") as file:
                            st.download_button(
                                "Download CSV",
                                file,
                                file_name=csv_filename,
                                use_container_width=True
                            )
            else:
                st.error("Failed to decrypt data for export")
        else:
            st.info("No data available to export")

# --- Footer ---
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: #666;'>"
    "🔐 Secure Data Vault | Built with Streamlit | © 2025"
    "</p>",
    unsafe_allow_html=True
)