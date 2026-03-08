import os
import datetime
import ollama
from .loading import Spinner
from .quarantine import quarantine_file
from .ml_engine import LocalScanner
from .scanner_api import VirusTotalAPI, AlienVaultAPI, MetaDefenderAPI, MalwareBazaarAPI
from . import network_isolation
from . import utils

class ScannerLogic:
    """Orchestrates the Multi-Tier Pipeline: Cloud -> ML -> LLM"""
    
    def __init__(self):
        config = utils.load_config()
        self.api_keys = config.get("api_keys", {})
        self.webhook_url = config.get("webhook_url", "")
        self.ml_scanner = LocalScanner() 
        self.session_log = []
        self.headless_mode = False # Tells the system if it's running as a daemon
        utils.init_db()
        
    def log_event(self, message: str, print_to_screen=True):
        """Persists scan output into an array for exportable session reporting."""
        if print_to_screen:
            print(message)
        self.session_log.append(message)

    def generate_llm_report(self, family_name: str, detected_apis: list, file_path: str, confidence_score: float, sha256: str, file_size_mb: float) -> str: 
        """Constructs semantic context and queries the Tier 3 Generative AI."""
        
        # MEMORY OPTIMIZATION: Truncate API list to prevent LLM Token Overflow
        max_apis = 50
        if detected_apis:
            api_context = "\n".join([f"- {api}" for api in detected_apis[:max_apis]])
            if len(detected_apis) > max_apis:
                api_context += f"\n- ... and {len(detected_apis) - max_apis} more mapped APIs."
        else:
            api_context = "None extracted. Possible API hashing or packing utilized."

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
        
        # SECURITY FIX: Prevent TOCTOU (Time-of-Check to Time-of-Use) Race Conditions
        if not os.path.exists(file_path):
            return

        if utils.is_excluded(file_path):
            self.log_event(f"[*] ALLOWLISTED: {os.path.basename(file_path)} bypassed scanning per enterprise policy.")
            return

        sha256 = utils.get_sha256(file_path)
        if not sha256:
            print("[-] Extraction Fault: Target file could not be read or was locked by the OS.")
            return
        
        malicious_sources = []

        try:
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        except OSError:
            print("[-] IO Error: File was moved or deleted before size calculation.")
            return

        self.log_event("-" * 60)
        self.log_event(f"[*] Target File: {os.path.basename(file_path)}")
        self.log_event(f"[*] Target SHA-256: {sha256}")
        
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        
       # --- TIER 1: MULTI-CLOUD INTELLIGENCE ---
        self.log_event("[*] Initializing Cloud Intelligence Routing...")
        
        # 1. Determine which engine to use
        selected_engine = "consensus"
        if not self.headless_mode:
            print("\n[?] Select Cloud Intelligence Engine:")
            print("1. VirusTotal")
            print("2. AlienVault OTX")
            print("3. MetaDefender")
            print("4. MalwareBazaar (Open Access)")
            print("5. Smart Consensus (Query all active APIs)")
            choice = input("Select an option (1-5): ").strip()
            
            mapping = {'1': 'virustotal', '2': 'alienvault', '3': 'metadefender', '4': 'malwarebazaar', '5': 'consensus'}
            selected_engine = mapping.get(choice, 'consensus')

        # 2. Execute the query based on selection
        cloud_result = None
        threat_source = "Cloud Intelligence"

        if selected_engine == 'consensus':
            self.log_event("[*] Running Smart Consensus across all active APIs...")
            malicious_sources = []
                
            # Query 1: MalwareBazaar
            if self.api_keys.get("malwarebazaar"):
                mb_res = MalwareBazaarAPI(self.api_keys["malwarebazaar"]).get_report(sha256)
                if mb_res:
                    self.log_event(f"    -> MalwareBazaar: {mb_res['verdict']} (Hits: {mb_res.get('engines_detected', 0)})")
                    if mb_res['verdict'] == 'MALICIOUS': malicious_sources.append("MalwareBazaar")
                else:
                    self.log_event("    -> MalwareBazaar: UNKNOWN (Not found in database)")

            # Query 2: VirusTotal
            if self.api_keys.get("virustotal"):
                vt_res = VirusTotalAPI(self.api_keys["virustotal"]).get_report(sha256)
                if vt_res:
                    self.log_event(f"    -> VirusTotal: {vt_res['verdict']} (Hits: {vt_res.get('engines_detected', 0)})")
                    if vt_res['verdict'] == 'MALICIOUS': malicious_sources.append("VirusTotal")
                else:
                    self.log_event("    -> VirusTotal: UNKNOWN (Not found in database)")

            # Query 3: AlienVault OTX
            if self.api_keys.get("alienvault"):
                otx_res = AlienVaultAPI(self.api_keys["alienvault"]).get_report(sha256)
                if otx_res:
                    self.log_event(f"    -> AlienVault OTX: {otx_res['verdict']} (Hits: {otx_res.get('engines_detected', 0)})")
                    if otx_res['verdict'] == 'MALICIOUS': malicious_sources.append("AlienVault")
                else:
                    self.log_event("    -> AlienVault OTX: UNKNOWN (Not found in database)")

            # Query 4: MetaDefender
            if self.api_keys.get("metadefender"):
                md_res = MetaDefenderAPI(self.api_keys["metadefender"]).get_report(sha256)
                if md_res:
                    self.log_event(f"    -> MetaDefender: {md_res['verdict']} (Hits: {md_res.get('engines_detected', 0)})")
                    if md_res['verdict'] == 'MALICIOUS': malicious_sources.append("MetaDefender")
                else:
                    self.log_event("    -> MetaDefender: UNKNOWN (Not found in database)")
                # Evaluate Aggregated Consensus
                if malicious_sources:
                    final_verdict = "MALICIOUS"
                    threat_source = f"Consensus ({', '.join(malicious_sources)})"
                else:
                    final_verdict = "SAFE"
                    threat_source = "Consensus (All Clean)"
                    
                cloud_result = {"verdict": final_verdict}
                self.log_event(f"[*] FINAL AGGREGATED VERDICT: {final_verdict}")

        else:
            # --- Single API Mode (Bypassed if Consensus is chosen) ---
            if selected_engine == 'virustotal' and self.api_keys.get("virustotal"):
                cloud_result = VirusTotalAPI(self.api_keys["virustotal"]).get_report(sha256)
                threat_source = "VirusTotal"
                if cloud_result and cloud_result['verdict'] == 'MALICIOUS':
                    malicious_sources.append("VirusTotal")

            elif selected_engine == 'alienvault' and self.api_keys.get("alienvault"):
                cloud_result = AlienVaultAPI(self.api_keys["alienvault"]).get_report(sha256)
                threat_source = "AlienVault OTX"
                if cloud_result and cloud_result['verdict'] == 'MALICIOUS':
                    malicious_sources.append("AlienVault")

            elif selected_engine == 'metadefender' and self.api_keys.get("metadefender"):
                cloud_result = MetaDefenderAPI(self.api_keys["metadefender"]).get_report(sha256)
                threat_source = "MetaDefender"
                if cloud_result and cloud_result['verdict'] == 'MALICIOUS':
                    malicious_sources.append("MetaDefender")

            elif selected_engine == 'malwarebazaar' and self.api_keys.get("malwarebazaar"):
                cloud_result = MalwareBazaarAPI(self.api_keys["malwarebazaar"]).get_report(sha256)
                threat_source = "MalwareBazaar"
                if cloud_result and cloud_result['verdict'] == 'MALICIOUS':
                    malicious_sources.append("MalwareBazaar")
                
            if cloud_result and selected_engine != 'consensus':
                self.log_event(f"[*] CLOUD VERDICT ({threat_source}): {cloud_result['verdict']} (Hits: {cloud_result.get('engines_detected', 0)})")

        # 3. Handle the Final Result
        if cloud_result:
            verdict = cloud_result['verdict']
            utils.save_cached_result(sha256, verdict)
            
            if verdict == "MALICIOUS":
                self._prompt_quarantine(file_path, sha256, threat_source, verdict)
                return
        else:
            self.log_event("[-] Cloud APIs skipped or unresponsive. Routing to local ML Engine.")

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

    def scan_hash(self, file_hash: str):
        """Dedicated pipeline for manual hash lookups using the Consensus Engine."""
        self.log_event("-" * 60)
        self.log_event(f"[*] Manual Hash Scan: {file_hash}")
        
        # 1. Tier 0: Check Local Cache First
        cached = utils.get_cached_result(file_hash)
        if cached:
            self.log_event(f"[*] CACHE HIT: Local DB indicates {cached['verdict']}")
            return

        # 2. Tier 1: Multi-Cloud Consensus
        self.log_event("[*] Running Smart Consensus across active APIs...")
        malicious_sources = []

        # Query 1: MalwareBazaar
        if self.api_keys.get("malwarebazaar"):
            mb_res = MalwareBazaarAPI(self.api_keys["malwarebazaar"]).get_report(file_hash)
            if mb_res:
                self.log_event(f"    -> MalwareBazaar: {mb_res['verdict']} (Hits: {mb_res.get('engines_detected', 0)})")
                if mb_res['verdict'] == 'MALICIOUS': malicious_sources.append("MalwareBazaar")
            else:
                self.log_event("    -> MalwareBazaar: UNKNOWN (Not found in database)")

        # Query 2: VirusTotal
        if self.api_keys.get("virustotal"):
            vt_res = VirusTotalAPI(self.api_keys["virustotal"]).get_report(file_hash)
            if vt_res:
                self.log_event(f"    -> VirusTotal: {vt_res['verdict']} (Hits: {vt_res.get('engines_detected', 0)})")
                if vt_res['verdict'] == 'MALICIOUS': malicious_sources.append("VirusTotal")
            else:
                self.log_event("    -> VirusTotal: UNKNOWN (Not found in database)")

        # Query 3: AlienVault OTX
        if self.api_keys.get("alienvault"):
            otx_res = AlienVaultAPI(self.api_keys["alienvault"]).get_report(file_hash)
            if otx_res:
                self.log_event(f"    -> AlienVault OTX: {otx_res['verdict']} (Hits: {otx_res.get('engines_detected', 0)})")
                if otx_res['verdict'] == 'MALICIOUS': malicious_sources.append("AlienVault")
            else:
                self.log_event("    -> AlienVault OTX: UNKNOWN (Not found in database)")

        # Query 4: MetaDefender
        if self.api_keys.get("metadefender"):
            md_res = MetaDefenderAPI(self.api_keys["metadefender"]).get_report(file_hash)
            if md_res:
                self.log_event(f"    -> MetaDefender: {md_res['verdict']} (Hits: {md_res.get('engines_detected', 0)})")
                if md_res['verdict'] == 'MALICIOUS': malicious_sources.append("MetaDefender")
            else:
                self.log_event("    -> MetaDefender: UNKNOWN (Not found in database)")
        # 3. Evaluate Consensus
        if malicious_sources:
            final_verdict = "MALICIOUS"
            self.log_event(f"\n[!] FINAL VERDICT: MALICIOUS (Detected by {', '.join(malicious_sources)})")
        else:
            final_verdict = "SAFE"
            self.log_event("\n[+] FINAL VERDICT: SAFE (All responding engines clean)")
            
        # Save to local database for future offline scans
        utils.save_cached_result(file_hash, final_verdict)

    def _handle_critical_ml_threat(self, file_path, sha256, file_size_mb, ml_result):
        """Isolates the complex LLM routing logic for Critical Threats."""
        
        fam_name = "Unknown"
        
        # --- 1. Prompt for Stage 2 Family Analysis ---
        if self.headless_mode:
            fam_ans = 'y'
        else:
            fam_ans = input("\n[?] Execute heavy Stage 2 Family Analysis? (Y/N): ").strip().lower()
            
        if fam_ans == 'y':
            self.log_event("[*] Running Stage 2 Classification...")
            fam_result = self.ml_scanner.scan_stage2(ml_result['features'])
            if fam_result:
                fam_name = fam_result.get('family_name', 'Unknown')
                self.log_event(f"[*] STAGE 2 CLASSIFICATION: {fam_name}")
        else:
            self.log_event("[*] Skipping Family Analysis.")
            
        # --- 2. Prompt for AI Analyst Report ---
        if self.headless_mode:
            ai_ans = 'y'
        else:
            ai_ans = input("\n[?] Generate local AI Analyst Report via Ollama? (Y/N): ").strip().lower()
            
        if ai_ans == 'y':
            loading_spinner = Spinner("[*] Generating Qwen AI Threat Report...")
            loading_spinner.start()
            report = self.generate_llm_report(fam_name, ml_result['detected_apis'], file_path, ml_result['score'] * 100, sha256, file_size_mb)
            loading_spinner.stop()
            
            self.log_event("\n--- AI Analyst Report ---")
            self.log_event(report)
        else:
            self.log_event("[*] Skipping AI Analyst Report.")
            
        # --- 3. ALWAYS Trigger Quarantine Prompt ---
        self._prompt_quarantine(file_path, sha256, "Local ML Engine", "CRITICAL RISK")

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

            # Creates Analysis Folder if it doesn't exist yet
            analysis_dir = "Analysis Files"
            if not os.path.exists(analysis_dir):
                os.makedirs(analysis_dir)
                
            filepath = os.path.join(analysis_dir, filename)
            
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write("="*60 + "\n CYBERSENTINEL SCAN REPORT\n")
                    f.write(f" Generated: {datetime.datetime.now()}\n" + "="*60 + "\n")
                    f.write("\n".join(self.session_log))
                    f.write("\n" + "="*60 + "\n END OF REPORT\n" + "="*60 + "\n")
                print(f"[+] Success! File saved as: {os.path.abspath(filepath)}")
            except Exception as e:
                print(f"[-] Save Error: {e}")