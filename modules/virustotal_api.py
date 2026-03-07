import requests
from . import utils

class VirusTotalAPI:
    """Handles all Tier 1 Cloud Intelligence network requests and data parsing."""
    
    BASE_URL = 'https://www.virustotal.com/api/v3/files/'

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"accept": "application/json", "x-apikey": api_key}

    def query_hash(self, sha256: str) -> dict:
        """
        Queries VT and returns the raw JSON response or HTTP error status.
        Uses the local cache to bypass network latency if possible.
        """
        # Tier 0 Intercept: Check Local DB First
        cached = utils.get_cached_result(sha256)
        if cached:
            return {"status": "CACHED", "verdict": cached['verdict'], "timestamp": cached['timestamp']}

        try:
            response = requests.get(self.BASE_URL + sha256, headers=self.headers)
            
            if response.status_code == 200:
                json_data = response.json()
                verdict = self._determine_verdict(json_data)
                
                # Save new cloud intelligence to local cache
                utils.save_cached_result(sha256, verdict)
                return {"status": "SUCCESS", "verdict": verdict, "data": json_data}
                
            elif response.status_code == 404:
                return {"status": "UNKNOWN", "message": "[-] File/Hash not found in VirusTotal database."}
            elif response.status_code == 401:
                return {"status": "ERROR", "message": "[-] VT API Error 401: Unauthorized. Please check your API Key."}
            elif response.status_code == 429:
                return {"status": "ERROR", "message": "[-] VT API Error 429: Rate limit exceeded."}
            else:
                return {"status": "ERROR", "message": f"[-] VT API Error: {response.status_code}"}
                
        except requests.exceptions.RequestException as e:
            return {"status": "ERROR", "message": f"[-] Network Error: {e}"}

    def _determine_verdict(self, json_data: dict) -> str:
        """Evaluates AV engine consensus to declare a final boolean state."""
        stats = json_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', 0)
        
        # Threat modeling consensus threshold
        return "MALICIOUS" if malicious_count >= 3 else "SAFE"