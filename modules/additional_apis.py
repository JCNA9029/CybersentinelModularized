import requests
from requests.exceptions import Timeout, RequestException

class AlienVaultAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {"X-OTX-API-KEY": self.api_key}

    def get_report(self, file_hash):
        if not self.api_key: return None
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
            resp = requests.get(url, headers=self.headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                # If it belongs to 1 or more known threat "pulses", it's bad.
                return {"verdict": "MALICIOUS" if pulse_count > 0 else "SAFE", "engines_detected": pulse_count}
            return None
        except Timeout:
            print("[-] AlienVault API Timeout. Engine skipped.")
            return None
        except RequestException as e:
            print(f"[-] AlienVault Network Error: {e}")
            return None
        except ValueError:
            print("[-] AlienVault Parsing Error: Invalid JSON response.")
            return None
        
        

class MetaDefenderAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {"apikey": self.api_key}

    def get_report(self, file_hash):
        if not self.api_key: return None
        try:
            url = f"https://api.metadefender.com/v4/hash/{file_hash}"
            resp = requests.get(url, headers=self.headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                threats = data.get("scan_results", {}).get("threats", 0)
                return {"verdict": "MALICIOUS" if threats > 0 else "SAFE", "engines_detected": threats}
            return None
        except Timeout:
            print("[-] MetaDefender API Timeout. Engine skipped.")
            return None
        except RequestException as e:
            print(f"[-] MetaDefender Network Error: {e}")
            return None
        except ValueError:
            print("[-] MetaDefender Parsing Error: Invalid JSON response.")
            return None

class MalwareBazaarAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def get_report(self, file_hash):
        if not self.api_key: return None
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            data = {"query": "get_info", "hash": file_hash}
            
            # Pass the required Auth-Key along with our browser disguise
            headers = {
                "Auth-Key": self.api_key,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CyberSentinel/1.0"
            }
            
            resp = requests.post(url, data=data, headers=headers, timeout=10)
            
            if resp.status_code == 200:
                result = resp.json()
                if result.get("query_status") == "ok":
                    return {"verdict": "MALICIOUS", "engines_detected": 1}
                return {"verdict": "SAFE", "engines_detected": 0}
            else:
                print(f"[-] MalwareBazaar API Error: Server returned HTTP {resp.status_code}")
                return None
                
        except Timeout:
            print("[-] MalwareBazaar API Timeout. Engine skipped.")
            return None
        except RequestException as e:
            print(f"[-] MalwareBazaar Network Error: {e}")
            return None
        except ValueError:
            print("[-] MalwareBazaar Parsing Error: Invalid JSON response.")
            return None
