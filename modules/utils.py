# This utility module provides core functions for encryption, configuration management, webhook alerts, internet connectivity checks, 
# file hashing, path sanitization, and local SQLite database management for caching scan results.
# It ensures that sensitive information like API keys are securely stored and that the EDR operates efficiently.
import hashlib
import socket
import json 
import os  
import base64
import binascii
import uuid
import sqlite3  
import datetime
import requests  # Optimization: Moved to the top of the file

CONFIG_FILE = "config.json"
DB_FILE = "threat_cache.db"

def get_machine_key() -> bytes:
    """
    Generates a dynamic 32-byte encryption key bound to the physical hardware MAC address.
    """
    hardware_id = str(uuid.getnode())
    return hashlib.sha256(hardware_id.encode()).digest()

def encrypt_key(api_key: str) -> str:
    """Scrambles the API key using a hardware-bound XOR cipher and Base64 encoding."""
    if not api_key: 
        return ""
    
    api_bytes = api_key.encode('utf-8')
    dynamic_key = get_machine_key()
    
    # XOR each byte of the API key against the hardware key
    xored = bytes(a ^ b for a, b in zip(api_bytes, dynamic_key * (len(api_bytes) // len(dynamic_key) + 1)))
    return base64.b64encode(xored).decode('utf-8')

def decrypt_key(encrypted_key: str) -> str:
    """Reverses the XOR cipher to retrieve the original API key in memory."""
    if not encrypted_key: 
        return ""
    try:
        enc_bytes = base64.b64decode(encrypted_key)
        dynamic_key = get_machine_key()
        
        xored = bytes(a ^ b for a, b in zip(enc_bytes, dynamic_key * (len(enc_bytes) // len(dynamic_key) + 1)))
        return xored.decode('utf-8')
    except (binascii.Error, UnicodeDecodeError):
        # SECURITY FIX: Catch specific cryptographic tampering errors
        print("[-] Security Warning: Local configuration file was tampered with or corrupted.")
        return ""

def load_config() -> dict:
    """Reads and decrypts multiple API keys and the Webhook URL."""
    config_data = {"api_keys": {}, "webhook_url": ""}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                data = json.load(f)
                
                # Retrieve the dictionary of keys
                keys = data.get("api_keys", {})
                
                # Backward compatibility: migrating your old VT key format automatically
                if "api_key" in data and not keys:
                    keys["virustotal"] = data.get("api_key", "")
                
                # Decrypt all saved keys
                config_data["api_keys"] = {k: decrypt_key(v) for k, v in keys.items() if v}
                config_data["webhook_url"] = decrypt_key(data.get("webhook_url", ""))
        except Exception:
            pass
    return config_data

def save_config(api_keys: dict, webhook_url: str = "") -> bool:
    """Encrypts a dictionary of API keys and writes to local storage."""
    try:
        # Encrypt every key in the dictionary before saving
        encrypted_keys = {k: encrypt_key(v) for k, v in api_keys.items() if v}
        with open(CONFIG_FILE, 'w') as f:
            json.dump({
                "api_keys": encrypted_keys,
                "webhook_url": encrypt_key(webhook_url)
            }, f)
        return True
    except Exception as e:
        print(f"[-] Failed to save configuration: {e}")
        return False

def send_webhook_alert(webhook_url: str, title: str, details: dict):
    """
    Transmits a JSON payload to a SOC webhook (e.g., Slack, Discord).
    Production Mode: Fails gracefully without interrupting the EDR pipeline.
    """
    if not webhook_url:
        return # Silently skip if the user hasn't set up a webhook
        
    payload = {
        "content": f"🚨 **CYBERSENTINEL ALERT: {title}** 🚨",
        "embeds": [{
            "title": "Automated Threat Intelligence Report",
            "color": 16711680, # Red
            "fields": [{"name": str(k), "value": str(v), "inline": False} for k, v in details.items()]
        }]
    }
    
    try:
        # Strict 3-second timeout so the malware scanner doesn't hang waiting on Discord
        requests.post(webhook_url, json=payload, timeout=3)
    except Exception:
        pass # Enterprise silent failure: keep the EDR running at all costs!
    
def check_internet(host="8.8.8.8", port=53, timeout=3) -> bool:
    """Pings Google's DNS to verify active external network routing."""
    try:
        socket.setdefaulttimeout(timeout)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
        return True
    except socket.error:
        return False
    
def get_sha256(file_path: str) -> str:
    """
    Generates a SHA-256 hash using chunked memory reading.
    Chunking (4096 bytes) ensures 50MB+ files do not crash system RAM.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None
    
def sanitize_path(path: str) -> str:
    """Strips hidden characters and quotes generated by terminal drag-and-drop operations."""
    if not path: 
        return ''
    return path.strip().lstrip("& ").strip("'\"").strip()

# --- DATABASE MANAGEMENT ---

def init_db():
    """Initializes the SQLite schema with safe memory contexts."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_cache (
                    sha256 TEXT PRIMARY KEY,
                    filename TEXT,  -- NEW COLUMN
                    verdict TEXT,
                    timestamp TEXT
                )
            ''')
    except sqlite3.Error as e:
        print(f"[-] Threat Cache Initialization Failed: {e}")

def save_cached_result(sha256: str, verdict: str, filename: str = "Unknown"):
    """Commits an analytical verdict to the local SQLite database."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('''
                INSERT OR REPLACE INTO scan_cache (sha256, filename, verdict, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (sha256, filename, verdict, now))
    except sqlite3.Error:
        pass

def get_cached_result(sha256: str) -> dict:
    """Executes an O(1) index lookup against the local threat cache."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT verdict, timestamp FROM scan_cache WHERE sha256 = ?', (sha256,))
            row = cursor.fetchone()
            
            if row:
                return {"verdict": row[0], "timestamp": row[1]}
    except sqlite3.Error:
        pass
    return None

def is_excluded(file_path: str) -> bool:
    """
    Enterprise Allowlist: Checks if the target file path matches 
    any directories or files explicitly excluded by the administrator.
    """
    exclusion_file = "exclusions.txt"
    
    # Auto-generate a template file if it doesn't exist yet
    if not os.path.exists(exclusion_file):
        try:
            with open(exclusion_file, 'w') as f:
                f.write("# CyberSentinel Enterprise Exclusion List\n")
                f.write("# Add directory paths or specific file paths below to bypass scanning.\n")
                f.write("# Example: C:\\Program Files\\MySafeCompany\\\n")
        except Exception:
            pass
        return False

    try:
        with open(exclusion_file, 'r') as f:
            # Read lines, ignore comments (#) and blank lines, convert to lowercase
            exclusions = [line.strip().lower() for line in f if line.strip() and not line.startswith('#')]
        
        target_path = file_path.lower()
        
        # Check if the target file's path contains any of the excluded strings
        for exc in exclusions:
            if exc in target_path:
                return True
    except Exception:
        pass
        
    return False