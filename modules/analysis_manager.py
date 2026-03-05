import os
import sys
import requests
import datetime
import ollama
from .loading import Spinner
from .quarantine import quarantine_file
from .ml_engine import LocalScanner
import psutil
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

    def scan_active_processes(self):
        """
        EDR Module: Enumerates active processes in memory.
        Filters out core Windows system binaries to prevent OS corruption.
        """
        self.log_event("\n--- Live Process Memory Triage ---")
        self.log_event("[*] Enumerating active processes...")

        suspicious_procs = []
        try:
            # Iterate through all running processes, grabbing their ID, Name, and File Path
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    exe_path = proc.info['exe']
                    # BLUE TEAM SAFEGUARD: Ignore standard Windows OS files to prevent accidental system death
                    if exe_path and "C:\\Windows" not in exe_path:
                        suspicious_procs.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'path': exe_path
                        })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    # Windows restricts access to SYSTEM processes unless running as Admin. We safely ignore them.
                    continue
        except Exception as e:
            self.log_event(f"[-] Failed to enumerate processes: {e}")
            return

        if not suspicious_procs:
            self.log_event("[+] No non-system processes found. System appears clean.")
            return

        # Display the live processes in a clean CLI table
        print(f"\n{'PID':<10} | {'Process Name':<25} | {'Executable Path'}")
        print("-" * 80)
        # Display the last 20 processes (usually the most recently launched)
        for p in suspicious_procs[-20:]: 
            # Truncate long paths for terminal readability
            display_path = p['path'] if len(p['path']) < 40 else "..." + p['path'][-37:]
            print(f"{p['pid']:<10} | {p['name']:<25} | {display_path}")

        choice = input("\n[?] Enter the PID of the process to scan (or press Enter to cancel): ").strip()
        if not choice.isdigit():
            return

        target_pid = int(choice)
        target_path = None
        
        # Match the user's PID to the physical file path
        for p in suspicious_procs:
            if p['pid'] == target_pid:
                target_path = p['path']
                break

        if target_path and os.path.exists(target_path):
            self.log_event(f"\n[*] Initiating EDR Scan on Process ID {target_pid}...")
            # Route the live process file directly into your existing scanning pipeline!
            self.scan_file(target_path)
        else:
            print("[-] Invalid PID or the process terminated before scanning.")

    def get_ai_explanation(self, family_name, detected_apis=None, file_path="", confidence_score=0.0, sha256="", file_size_mb=0.0): 
        # 1. Format the API list or provide a technical reason for its absence
        if detected_apis and len(detected_apis) > 0:
            api_context = "\n".join([f"- {api}" for api in detected_apis])
        else:
            api_context = "None extracted. The file is likely utilizing a packer (e.g., UPX), encrypted payloads, or API hashing to evade static analysis."

        # 2. Prevent hallucination on unknown Family IDs
        family_context = family_name
        if "Family ID #" in family_name:
            family_context += " (Heuristic match. Instruct analyst to focus entirely on behavioral API analysis rather than family history.)"

        # 3. The Strict EDR Prompt
        prompt = f"""
        [SYSTEM: EDR TRIAGE REPORT GENERATION]
        Target File: {os.path.basename(file_path)}
        Target SHA256: {sha256}
        File Size: {file_size_mb:.2f} MB
        Malware Classification: {family_context}
        AI Confidence Score: {confidence_score:.2f}%
        Extracted Windows APIs:
        {api_context}

        TASK: Generate a highly technical malware triage report. 
        If specific APIs are listed, explain EXACTLY how they are chained together to perform malicious actions. Map the APIs to MITRE ATT&CK tactics (e.g., Process Injection, Defense Evasion, Command and Control) where applicable.
        Do not use conversational filler. Do not introduce yourself. 

        Format the output EXACTLY using these four headers:

        ### 🔴 Threat Classification
        (1-2 sentences explaining the core threat of the malware family or the potential behavior if the family is an unknown heuristic match.)

        ### ⚙️ API Behavioral Analysis
        (Explain the technical intent behind the specific APIs detected. If no APIs were detected, explain the specific evasion techniques likely being used.)

        ### ⚠️ System Impact & Risk
        (What exactly happens to the victim's data, memory, or network capability?)

        ### 🛡️ Recommended Mitigation
        (Actionable, technical isolation and remediation steps beyond just "delete the file".)

        ### 🎯 Generated YARA Rule
        (Write a valid, strictly formatted YARA rule to detect this threat. 
        - Include a 'meta' section with description, author="CyberSentinel Automated Triage", date, and the provided SHA256 hash.
        - Include a 'strings' section containing the detected APIs (if any).
        - Include a 'condition' section. The condition MUST check that the file is a Windows PE by verifying the magic byte: `uint16(0) == 0x5A4D`. It should also match the strings or file size.)
        """
        
        try:
            # Setting a low temperature (e.g., 0.2) forces the LLM to be highly analytical and less "creative"
            response = ollama.chat(model='qwen2.5:3b', messages=[
                {'role': 'system', 'content': 'You are a strictly analytical, automated Endpoint Detection and Response (EDR) triage engine.'},
                {'role': 'user', 'content': prompt},
            ], options={'temperature': 0.2})
            
            return response['message']['content']
        except Exception as e:
            return f"[-] Analyst Engine Offline: {e}"

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
        if self.api_key:
            vt_result = self.query_virustotal(sha256, is_batch=False)
            
            if vt_result == "MALICIOUS":
                self.log_event("[!] Action Guidance: Cloud consensus confirms this is a known threat.")
                choice = input("\n[?] Do you want to quarantine this file immediately? (Y/N): ").strip().upper()
                if choice == 'Y':
                    quarantine_file(file_path)
                return # End scan. VT handled the threat.
                
            elif vt_result == "SAFE":
                self.log_event("[+] Action Guidance: VirusTotal confirms this file is safe. No further analysis needed.")
                return # End scan. The file is perfectly clean.
                
            # If vt_result is "UNKNOWN" or "ERROR", the code simply continues downward...
            self.log_event("[*] Proceeding to Local ML Fallback...")
        
        # Layer 2: Local AI (With Size Limit)
        if file_size_mb > 50.0:
            self.log_event("\n--- Local AI Scanner ---")
            self.log_event("[!] File exceeds the 50MB threshold for local Machine Learning extraction.")
            self.log_event("[*] Action Guidance: Rely on VirusTotal Cloud results or scan manually.")
        else:
            # Pass the data.
            self.run_local_ml(file_path, sha256, file_size_mb)

        #VirusTotal 
    def query_virustotal(self, sha256, force_details=False, is_batch=False):
        url = BASE_URL + sha256
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            # CAPTURE the string from parse_vt_response and pass it up!
            return self.parse_vt_response(response.json(), force_details, is_batch)
            
        elif response.status_code == 404:
            if not is_batch: 
                self.log_event("[-] File/Hash not found in VirusTotal database.")
            return "UNKNOWN" # Triggers the local ML
            
        elif response.status_code == 401:
            self.log_event("[-] VT API Error 401: Unauthorized. Please check your API Key.")
            return "ERROR"
            
        elif response.status_code == 429:
            self.log_event("[-] VT API Error 429: Rate limit exceeded. You are scanning too fast!")
            return "ERROR"
            
        else:
            self.log_event(f"[-] VT API Error: {response.status_code} - {response.text}")
            return "ERROR"
        
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

        malicious_count = stats.get('malicious', 0)
        if malicious_count >= 3:
            return "MALICIOUS"
        else:
            return "SAFE"

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
    def run_local_ml(self, file_path, sha256, file_size_mb):
        self.log_event("\n--- Local AI Scanner ---")
        result = self.ml_scanner.scan_stage1(file_path)
        #getting the score, verdict and the detected apis from the result of the local machine learning analysis
        if result:
            score = result['score']
            verdict = result['verdict']
            apis = result['detected_apis']
            
            self.log_event(f"[*] Local ML Verdict: {verdict} (Confidence: {score:.2%})")
            
            if verdict == "CRITICAL RISK":
                self.log_event("[!] Action Guidance: High confidence threat. Quarantine recommended.")
                print("")

                ans = input("[?] Do you want to run the heavy Stage 2 Family Analysis to identify the malware strain? (Y/N): ").strip().lower()
                fam_name = "Unknown"
                if ans == 'y':
                    fam_result = self.ml_scanner.scan_stage2(result['features'])
                    if fam_result:
                        fam_name = fam_result.get('family_name', 'Unknown')
                        self.log_event(f"[*] STAGE 2 CLASSIFICATION: {fam_name}")
        
                # ... [previous code] ...
                
                loading_spinner = Spinner("[*] Consulting Local AI Analyst for a threat report...")
                loading_spinner.start()
                
                # Inject the extracted behavioral telemetry (APIs) and inference confidence 
                # into the LLM context window for semantic evaluation and MITRE ATT&CK mapping.
                # Pass the hash and size into the prompt.
                report = self.get_ai_explanation(fam_name, apis, file_path, score * 100, sha256, file_size_mb)
                
                loading_spinner.stop()
                
                # ... [rest of code] ...
                
                self.log_event("\n--- AI Analyst Report ---")
                self.log_event(report)
                    
                choice = input("\n[?] Do you want to quarantine this file immediately? (Y/N): ").strip().upper()
                if choice == 'Y':
                    quarantine_file(file_path)
                else:
                    print("[!] Action aborted. The file remains in its original location.")
                    
            elif verdict == "SUSPICIOUS":
                self.log_event("[!] Warning: Local ML detected anomalies but lacks confidence for isolation.")
                self.log_event("[!] Action Guidance: As this file is unknown to Cloud AV, manual dynamic analysis in a sandbox is recommended before execution.")
            else:
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
