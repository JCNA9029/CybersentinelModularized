import hashlib
import socket
import json 
import os  
import base64
import uuid

CONFIG_FILE = "config.json"

def get_machine_key() -> bytes:
    """
    Generates a dynamic encryption key bound to the physical hardware of the machine.
    Uses the MAC address and hashes it via SHA-256 to create a secure 32-byte key.
    """
    hardware_id = str(uuid.getnode())
    return hashlib.sha256(hardware_id.encode()).digest()

def encrypt_key(api_key):
    """Scrambles the API key using XOR and Base64."""
    if not api_key: return ""
    
    api_bytes = api_key.encode('utf-8')
    dynamic_key = get_machine_key()  # Fetch the hardware-bound key
    
    # XOR each byte of the API key with our dynamic key
    xored = bytes(a ^ b for a, b in zip(api_bytes, dynamic_key * (len(api_bytes) // len(dynamic_key) + 1)))
    return base64.b64encode(xored).decode('utf-8')

def decrypt_key(encrypted_key):
    """Unscrambles the API key back to its original form."""
    if not encrypted_key: return ""
    try:
        enc_bytes = base64.b64decode(encrypted_key)
        dynamic_key = get_machine_key()  # Fetch the hardware-bound key
        
        # Reversing an XOR cipher is just doing XOR again
        xored = bytes(a ^ b for a, b in zip(enc_bytes, dynamic_key * (len(enc_bytes) // len(dynamic_key) + 1)))
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