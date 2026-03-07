import os
import sys
import datetime
import ollama
from .loading import Spinner
from .quarantine import quarantine_file
from .ml_engine import LocalScanner
from .virustotal_api import VirusTotalAPI
from . import network_isolation
from . import utils

class ScannerLogic:
    """Orchestrates the Multi-Tier Pipeline: Cloud -> ML -> LLM"""
    
    def __init__(self):
        config = utils.load_config()
        self.api_key = config.get("api_key", "")
        self.webhook_url = config.get("webhook_url", "")
        self.ml_scanner = LocalScanner()
        self.session_log = []
        self.headless_mode = False # NEW: Tells the system if it's running as a daemon
        utils.init_db()
        
    def log_event(self, message: str, print_to_screen=True):
        """Persists scan output into an array for exportable session reporting."""
        if print_to_screen:
            print(message)
        self.session_log.append(message)

    def generate_llm_report(self, family_name, detected_apis, file_path, confidence_score, sha256, file_size_mb) -> str: 
        """Constructs semantic context and queries the Tier 3 Generative AI."""
        api_context = "\n".join([f"- {api}" for api in detected_apis]) if detected_apis else "None extracted. Possible API hashing or packing utilized."
        family_context = family_name + (" (Heuristic match. Focus on behavioral APIs.)" if "Family ID #" in family_name else "")

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
        If specific APIs are listed, explain EXACTLY how they are chained together to perform malicious actions. Map the APIs to MITRE ATT&CK tactics (e.g., Process Injection).
        Do not use conversational filler. Do not introduce yourself. 

        Format the output EXACTLY using these four headers:

        ### 🔴 Threat Classification
        (1-2 sentences explaining the core threat.)

        ### ⚙️ API Behavioral Analysis
        (Explain the technical intent behind the specific APIs detected.)

        ### ⚠️ System Impact & Risk
        (What happens to the victim's data, memory, or network capability?)

        ### 🛡️ Recommended Mitigation
        (Actionable, technical isolation steps.)

        ### 🎯 Generated YARA Rule
        (Write a valid YARA rule. Include a 'condition' section that MUST check the PE magic byte: `uint16(0) == 0x5A4D`.)
        """
        
        try:
            # Temperature 0.2 restricts hallucination and forces technical formatting
            response = ollama.chat(model='qwen2.5:3b', messages=[
                {'role': 'system', 'content': 'You are a strictly analytical, automated Endpoint Detection and Response (EDR) triage engine.'},
                {'role': 'user', 'content': prompt},
            ], options={'temperature': 0.2})
            return response['message']['content']
        except Exception as e:
            return f"[-] LLM Analyst Offline: {e}"

    def scan_file(self, file_path: str):
        """Main routing pipeline for physical file scans."""
        
        # --- TIER 00: ENTERPRISE EXCLUSION LIST ---
        # Stop immediately if the file is an authorized business application
        if utils.is_excluded(file_path):
            self.log_event(f"[*] ALLOWLISTED: {os.path.basename(file_path)} bypassed scanning per enterprise policy.")
            return

        sha256 = utils.get_sha256(file_path)
        if not sha256:
            print("[-] Extraction Fault: Target file could not be read.")
            return

        self.log_event("-" * 60)
        self.log_event(f"[*] Target File: {os.path.basename(file_path)}")
        self.log_event(f"[*] Target SHA-256: {sha256}")
        
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        
        # --- TIER 1: CLOUD API ---
        if self.api_key:
            vt_api = VirusTotalAPI(self.api_key)
            result = vt_api.query_hash(sha256)
            
            if result["status"] == "CACHED":
                self.log_event(f"[*] CACHE HIT: Local DB indicates {result['verdict']}")
                if result["verdict"] in ["MALICIOUS", "CRITICAL RISK"]:
                    self._prompt_quarantine(file_path, sha256, "VirusTotal Cloud API", result["verdict"])
                return
                
            elif result["status"] == "SUCCESS":
                self._format_vt_output(result["data"])
                if result["verdict"] == "MALICIOUS":
                    self.log_event("[!] Action Guidance: Cloud consensus confirms a known threat.")
                    self._prompt_quarantine(file_path, sha256, "VirusTotal Cloud API", result["verdict"])
                    return
                elif result["verdict"] == "SAFE":
                    self.log_event("[+] Action Guidance: Cloud confirms file is safe.")
                    return
            else:
                self.log_event(result["message"])

        # --- TIER 2: LOCAL ML ENGINE ---
        if file_size_mb > 50.0:
            self.log_event(f"[!] File ({file_size_mb:.2f}MB) exceeds local ML extraction limits. Skipping.")
            return

        self.log_event("\n[*] Proceeding to Tier 2: Offline ML Fallback...")
        ml_result = self.ml_scanner.scan_stage1(file_path)
        
        if not ml_result:
            self.log_event("[-] ML Engine failed to process file.")
            return

        verdict = ml_result['verdict']
        self.log_event(f"[*] Local ML Verdict: {verdict} (Confidence: {ml_result['score']:.2%})")
        utils.save_cached_result(sha256, verdict)
            
        if verdict == "CRITICAL RISK":
            self._handle_critical_ml_threat(file_path, sha256, file_size_mb, ml_result)
        elif verdict == "SUSPICIOUS":
            self.log_event("[!] Warning: Anomalies detected, but insufficient confidence for isolation. Sandbox testing advised.")
        else:
            self.log_event("[+] File structure aligns with safe parameters.")

    def _handle_critical_ml_threat(self, file_path, sha256, file_size_mb, ml_result):
        """Isolates the complex LLM routing logic for Critical Threats."""
        
        # HEADLESS FIX: Auto-approve Stage 2 if running in the background
        if self.headless_mode:
            ans = 'y'
        else:
            ans = input("[?] Execute heavy Stage 2 Family Analysis? (Y/N): ").strip().lower()
            
        fam_name = "Unknown"
        if ans == 'y':
            fam_result = self.ml_scanner.scan_stage2(ml_result['features'])
            if fam_result:
                fam_name = fam_result.get('family_name', 'Unknown')
                self.log_event(f"[*] STAGE 2 CLASSIFICATION: {fam_name}")
        
        loading_spinner = Spinner("[*] Generating Qwen AI Threat Report...")
        loading_spinner.start()
        report = self.generate_llm_report(fam_name, ml_result['detected_apis'], file_path, ml_result['score'] * 100, sha256, file_size_mb)
        loading_spinner.stop()
        
        self.log_event("\n--- AI Analyst Report ---")
        self.log_event(report)
        self._prompt_quarantine(file_path)

    def _prompt_quarantine(self, file_path, sha256, threat_source, verdict):
        """Centralized prompt for active mitigation and network containment."""
        
        # 1. Dispatch telemetry BEFORE cutting the network
        if self.webhook_url:
            utils.send_webhook_alert(
                self.webhook_url, 
                title=f"Threat Detected on Endpoint",
                details={
                    "File": os.path.basename(file_path),
                    "SHA-256": sha256,
                    "Detection Source": threat_source,
                    "Verdict": verdict,
                    "Containment": "Initiating Network Isolation"
                }
            )
            self.log_event("[*] Alert dispatched to SOC Webhook.")

        # 2. HEADLESS FIX: Auto-Quarantine and Auto-Isolate
        if self.headless_mode:
            self.log_event("[!] HEADLESS MODE: Auto-quarantining threat to protect system.")
            quarantine_file(file_path)
            self.log_event("[!] HEADLESS MODE: Severing network connection to stop C2 traffic.")
            network_isolation.isolate_network()
            return

        # 3. Interactive CLI Mode
        choice = input("\n[?] Authorize immediate quarantine and network isolation? (Y/N): ").strip().upper()
        if choice == 'Y':
            quarantine_file(file_path)
            network_isolation.isolate_network()
            
    def save_session_log(self):
        """Writes the session array to disk upon user exit."""
        if not self.session_log:
            return

        print("\n" + "="*50)
        ans = input("[?] Would you like to save these results to a forensic .txt log? (Y/N): ").strip().lower()
        if ans == 'y':
            filename = input("[>] Enter filename (e.g., my_report): ").strip() or "scan_results"
            if not filename.endswith('.txt'): filename += '.txt'
            
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("="*60 + "\n CYBERSENTINEL SCAN REPORT\n")
                    f.write(f" Generated: {datetime.datetime.now()}\n" + "="*60 + "\n")
                    f.write("\n".join(self.session_log))
                    f.write("\n" + "="*60 + "\n END OF REPORT\n" + "="*60 + "\n")
                print(f"[+] Success! File saved as: {os.path.abspath(filename)}")
            except Exception as e:
                print(f"[-] Save Error: {e}")