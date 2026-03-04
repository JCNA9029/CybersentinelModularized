import os
import sys
import requests
import datetime
import ollama
from .loading import Spinner
from .ml_engine import LocalScanner
from . import utils

BASE_URL = 'https://www.virustotal.com/api/v3/files/'

class ScannerLogic:
    def __init__(self):
        self.api_key = None
        self.headers = {"accept": "application/json"}
        self.ml_scanner = LocalScanner()
        self.session_log = []
        
     #logs the event for the text file and also prints it to the screen
    def log_event(self, message, print_to_screen=True):
        if print_to_screen:
            print(message)
        self.session_log.append(message)

    def get_ai_explanation(self, family_name, detected_apis=None, file_path=""): #AI Prompts
        api_context = ", ".join(detected_apis) if detected_apis else "No suspicious APIs detected."
        prompt = f"""
        ANALYSIS TASK:
        Malware Family: {family_name}
        Detected API Imports: {api_context}
        Target File: {os.path.basename(file_path)}

        As a Senior Malware Researcher, explain:
        1. The core threat of this family.
        2. How the specific APIs detected ({api_context}) are likely being used by this malware.
        3. The risk to the user's data.
        4. Any recommended immediate actions for the user.

        Be precise and on point. Only show the results and do not introduce yourself.
        """
        try:
            response = ollama.chat(model='llama3:8b', messages=[
                {'role': 'system', 'content': 'You are a professional cybersecurity analyst.'},
                {'role': 'user', 'content': prompt},
            ])
            return response['message']['content']
        except Exception as e:
            return f"Analyst Offline: {e}"

    def scan_file(self, file_path):
        sha256 = utils.get_sha256(file_path)
        if not sha256:
            print("[-] File could not be read.")
            return

        # --- SEPARATOR LINE ---
        self.log_event("-" * 60)
        
        
        self.log_event(f"[*] Target File: {os.path.basename(file_path)}")
        self.log_event(f"[*] Target SHA256: {sha256}")
        
        # Check File Size (in Megabytes)
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        self.log_event(f"[*] File Size: {file_size_mb:.2f} MB")
        
        # Layer 1: Cloud API
        vt_success = False
        if self.api_key:
            vt_success = self.query_virustotal(sha256, is_batch=False)
            if vt_success:
                return
            self.log_event("[*] Proceeding to Local ML Fallback...")
        
        # Layer 2: Local AI (With Size Limit)
        if file_size_mb > 50.0:
            self.log_event("\n--- Local AI Scanner ---")
            self.log_event("[!] File exceeds the 50MB threshold for local Machine Learning extraction.")
            self.log_event("[*] Action Guidance: Rely on VirusTotal Cloud results or scan manually.")
        else:
            # Only run the heavy ML if the file is a reasonable size
            self.run_local_ml(file_path)

        #VirusTotal 
    def query_virustotal(self, sha256, force_details=False, is_batch=False):
        url = BASE_URL + sha256
        response = requests.get(url, headers=self.headers)
        
        #Response handling with more detailed error messages and user guidance based on the status code returned by the VirusTotal API
        if response.status_code == 200:
            self.parse_vt_response(response.json(), force_details, is_batch)
            return True
        elif response.status_code == 404:
            if not is_batch: 
                self.log_event("[-] File/Hash not found in VirusTotal database.")
            return False
        elif response.status_code == 400:
            self.log_event(f"[-] VT API Error 400: Bad Request. The hash '{sha256}' is malformed or does not exist.")
            return False
        elif response.status_code == 401:
            self.log_event("[-] VT API Error 401: Unauthorized. Please check your API Key.")
            return False
        elif response.status_code == 429:
            self.log_event("[-] VT API Error 429: Rate limit exceeded. You are scanning too fast!")
            return False
        else:
            self.log_event(f"[-] VT API Error: {response.status_code} - {response.text}")
            return False

        #Shows the results from the VirusTotal in a readable format
    def parse_vt_response(self, json_data, force_details, is_batch):
        attributes = json_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        scan_results = attributes.get('last_analysis_results', {})
        other_names = attributes.get('names', [])
        meaningful_name = attributes.get('meaningful_name', "Unknown")

        summary = (
            f"\n--- VirusTotal Cloud Results ---\n"
            f"Main Detected Name:   {meaningful_name}\n"
            f"Malicious Detections: {stats.get('malicious', 0)}\n"
            f"Harmless Results:     {stats.get('harmless', 0)}\n"
            f"Suspicious Results:   {stats.get('suspicious', 0)}"
        )
        self.log_event(summary)

        #Gives idea on what the other name of the scanned file is and also gives the option to show the detailed results of the scan if the user wants to see it
        if other_names:
            alt_names_str = ", ".join(other_names[:5])
            self.log_event(f"[*] Also known as: {alt_names_str}")

            show_details = force_details
            if not is_batch and not force_details:
                ans = input("\nDo you want to see the detailed list of AV engine results? (Y/N): ").strip().lower()
                show_details = (ans == 'y')

            if show_details:
                details = "\n--- Detailed AV Engine Results ---\n"
                for engine, result in scan_results.items():
                    category = result.get('category', 'undetected')
                    if category == 'malicious':
                        details += f"[!] {engine}: {category.upper()} - {result.get('result', 'Unknown')}\n"
                    elif category != 'undetected': 
                        details += f"[*] {engine}: {category.capitalize()}\n"
                
                if details.strip() == "--- Detailed AV Engine Results ---":
                    details += "All reporting engines marked this as Undetected/Safe.\n"
                self.log_event(details)

        #Labeling the risk based on the number of detections and giving the user a guidance on what to do next
    def get_risk_label(self, score, is_malicious):
        if is_malicious:
            if score > 0.90: return "CRITICAL RISK", "Certain"
            elif score > 0.75: return "HIGH RISK", "Strong"
            else: return "SUSPICIOUS", "Tentative"
        else:
            confidence = 1 - score
            if confidence > 0.90: return "SAFE", "High"
            elif confidence > 0.70: return "CLEAN", "Moderate"
            else: return "UNKNOWN/LOW RISK", "Weak"

        #Local Machine Learning Analysis
    def run_local_ml(self, file_path):
        self.log_event("\n--- Local AI Scanner ---")
        result = self.ml_scanner.scan_stage1(file_path)
        
        if result:
            score = result['score']
            is_malicious = result['is_malicious']
            label, confidence_type = self.get_risk_label(score, is_malicious)
            
            if is_malicious:
                self.log_event(f"[!] VERDICT: {label}")
                self.log_event(f"[*] Confidence: {confidence_type} ({score:.2%})")
                self.log_event("[!] Action Guidance: Quarantine this file immediately.")
                print("")

                # If the file is flagged as malicious, offer the option to run the heavy family classification model for more insights
                ans = input("[?] Do you want to run the heavy Stage 2 Family Analysis to identify the malware strain? (Y/N): ").strip().lower()
                if ans == 'y':
                    fam_result = self.ml_scanner.scan_stage2(result['features'])
                    if fam_result:
                        name = fam_result.get('family_name') or fam_result.get('name') or "Unknown"
                        self.log_event(f"[*] STAGE 2 CLASSIFICATION: {fam_result.get('family_name', 'Unknown')}")
        
                    loading_spinner = Spinner("[*] Consulting Local AI Analyst for a threat report...")
                    loading_spinner.start()
                    report = self.get_ai_explanation(fam_result.get('family_name', 'Unknown'), [], file_path)
                    loading_spinner.stop()
                    self.log_event("\n--- AI Analyst Report ---")
                    self.log_event(report)
            else:
                self.log_event(f"[+] VERDICT: {label}")
                self.log_event(f"[*] Confidence: {confidence_type} ({1-score:.2%})")
                self.log_event("[+] Action Guidance: No immediate threat found. File is likely safe.")
        else:
            self.log_event("[-] Analysis failed: The file could not be processed by the ML engine.")

    def exit_program(self):
        if not self.session_log:
            print("\n[-] No scan data recorded in this session to save.")
            print("Exiting. Stay secure!")
            sys.exit()

        #Separator line before the save prompt
        print("\n" + "="*50)
        ans = input("[?] Would you like to save these results to a file? (Y/N): ").strip().lower()
        if ans == 'y':
            filename = input("[>] Enter filename (e.g., my_report): ").strip()
            if not filename: filename = "scan_results"
            if not filename.endswith('.txt'): filename += '.txt'
            
            #Scan report formatting and saving
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("="*60 + "\n")
                    f.write(" CYBERSENTINEL SCAN REPORT\n")
                    f.write(f" Generated: {datetime.datetime.now()}\n")
                    f.write("="*60 + "\n")
                    f.write("\n".join(self.session_log))
                    f.write("\n" + "="*60 + "\n")
                    f.write(" END OF REPORT\n")
                    f.write("="*60 + "\n\n")
                print(f"[+] Success! File saved as: {os.path.abspath(filename)}")
            except Exception as e:
                print(f"[-] Save Error: {e}")
                    
        print("\nExiting. Stay secure!")
        sys.exit()
