import hashlib
import socket
import json 
import os  
import base64

CONFIG_FILE = "config.json"

CONFIG_FILE = "config.json"
SECRET_KEY = b"CyberSentinel2026" # The internal key used to scramble the data

def encrypt_key(api_key):
    """Scrambles the API key using XOR and Base64."""
    if not api_key: return ""
    api_bytes = api_key.encode('utf-8')
    # XOR each byte of the API key with our Secret Key
    xored = bytes(a ^ b for a, b in zip(api_bytes, SECRET_KEY * (len(api_bytes) // len(SECRET_KEY) + 1)))
    return base64.b64encode(xored).decode('utf-8')

def decrypt_key(encrypted_key):
    """Unscrambles the API key back to its original form."""
    if not encrypted_key: return ""
    try:
        enc_bytes = base64.b64decode(encrypted_key)
        # Reversing an XOR cipher is just doing XOR again
        xored = bytes(a ^ b for a, b in zip(enc_bytes, SECRET_KEY * (len(enc_bytes) // len(SECRET_KEY) + 1)))
        return xored.decode('utf-8')
    except Exception:
        return ""

def load_config():
    """Reads and decrypts the API key from the local config file."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                data = json.load(f)
                encrypted = data.get("api_key", "")
                return decrypt_key(encrypted)
        except Exception:
            return ""
    return ""

def save_config(api_key):
    """Encrypts and saves the API key to a local config file."""
    try:
        encrypted = encrypt_key(api_key)
        with open(CONFIG_FILE, 'w') as f:
            json.dump({"api_key": encrypted}, f)
        return True
    except Exception as e:
        print(f"[-] Failed to save configuration: {e}")
        return False
    
    #Checking the internet connection by trying to connect to Google's DNS server.
def check_internet(host="8.8.8.8", port=53, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error:
        return False
    
    #SHA 256 hashing function to generate a unique identifier for files
def get_sha256(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None
    
    #sanitation to remove unnecessary characters from the file.
def sanitize_path(path):
    if not path: return ''
    return path.strip().lstrip("& ").strip("'\"").strip()