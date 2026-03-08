import argparse
import os
import sys
import time
from modules import ScannerLogic, utils
from modules.virustotal_api import VirusTotalAPI
from modules.live_edr import get_target_process_path
from modules.network_isolation import restore_network

class CyberSentinelUI:
    def __init__(self):
        self.logic = ScannerLogic()

    def print_banner(self):
        banner = r"""
  ____ _   _ ____  _____ ____  ____  _____ _   _ _____ ___ _   _ _____ _     
 / ___| \ | | __ )| ____|  _ \/ ___|| ____| \ | |_   _|_ _| \ | | ____| |    
| |   | \ | |  _ \|  _| | |_) \___ \|  _| |  \| | | |  | ||  \| |  _| | |    
| |___| |_| | |_) | |___|  _ < ___) | |___| |\  | | |  | || |\  | |___| |___ 
 \____|\__, |____/|_____|_| \_\____/|_____|_| \_| |_| |___|_| \_|_____|_____|
       |___/
        """
        print(banner)

    def setup_api(self):
        """Authenticates Tier 1 Cloud capability upon instantiation."""
        config = utils.load_config()
        
        # Ensure api_keys is a dictionary
        self.logic.api_keys = config.get("api_keys", {})
        self.logic.webhook_url = config.get("webhook_url", "")
        
        if self.logic.api_keys:
            print("[+] Welcome back! Loaded saved Configuration.")
        else:
            print("\n--- First Time Setup ---")
            key = input("Enter your VirusTotal API Key (leave blank to skip VT): ").strip()
            if key:
                # Save it properly into the dictionary!
                self.logic.api_keys["virustotal"] = key
                # Pass the entire dictionary to the vault
                utils.save_config(self.logic.api_keys, self.logic.webhook_url)
                self.logic.log_event("[+] API Key saved successfully for future use.")
            else:
                self.logic.log_event("\n[!] Running in Local Machine Learning Mode only.")

    def update_settings(self):
        """Exposed API and Webhook configuration interface."""
        print("\n--- Settings: Multi-Cloud Configuration ---")
        
        # Ensure we have a dictionary to work with
        if not hasattr(self.logic, 'api_keys') or not isinstance(self.logic.api_keys, dict):
            self.logic.api_keys = {}

        engines = ["virustotal", "alienvault", "metadefender", "malwarebazaar"]
        
        for engine in engines:
            current = "Active/Saved" if self.logic.api_keys.get(engine) else "Not Set"
            print(f"[*] {engine.capitalize()} API Key: {current}")
            new_key = input(f"Enter new {engine.capitalize()} Key (Type 'CLEAR' to remove, Enter to skip): ").strip()
            
            if new_key.upper() == 'CLEAR':
                self.logic.api_keys.pop(engine, None)
                print(f"[+] {engine.capitalize()} key cleared.")
            elif new_key:
                self.logic.api_keys[engine] = new_key

        current_webhook = "Active/Saved" if self.logic.webhook_url else "Not Set"
        print(f"\n[*] SOC Webhook Status: {current_webhook}")
        new_webhook = input("Enter new Webhook URL (Type 'CLEAR' to remove, Enter to skip): ").strip()
        
        if new_webhook.upper() == 'CLEAR':
            self.logic.webhook_url = ""
        elif new_webhook:
            self.logic.webhook_url = new_webhook
            
        # Save the whole dictionary
        utils.save_config(self.logic.api_keys, self.logic.webhook_url)
        print("[+] Global Configuration updated successfully.")

    def _continuous_loop(self, action_func, prompt_msg):
        """Helper abstraction to keep the user in a continuous workflow."""
        while True:
            action_func()
            if input(f"\n[?] {prompt_msg} (Y to continue / Any other key for Menu): ").strip().upper() != 'Y':
                break

    def _menu_analyze_path(self):
            """Intelligently handles both single files and batch directory scans."""
            path = input("\nDrag and drop a file or folder to scan (or press Enter to cancel): ").strip().strip('"').strip("'")
            
            if not path:
                return
                
            if not os.path.exists(path):
                print("[-] Error: Path does not exist.")
                return
                
            # SMART ROUTING: If it's a single file, just scan it.
            if os.path.isfile(path):
                self.logic.scan_file(path)
                
            # SMART ROUTING: If it's a folder, run the batch loop.
            elif os.path.isdir(path):
                print(f"\n[*] Initiating Batch Scan on directory: {path}")
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        print("\n" + "="*50)
                        self.logic.scan_file(file_path)
                print(f"\n[+] Batch Scan Complete for: {path}")

    def _menu_analyze_hash(self):
        """Intelligently handles both single hashes and batch .txt files."""
        user_input = input("\nPaste a Hash OR drag a .txt file (or press Enter to cancel): ").strip().strip('"').strip("'")
        
        if not user_input:
            return
            
        # SMART ROUTING: Check if the input is a batch text file
        if os.path.isfile(user_input) and user_input.endswith('.txt'):
            print(f"\n[*] Reading IoC file: {user_input}")
            try:
                with open(user_input, 'r', encoding='utf-8') as f:
                    lines = [line.strip() for line in f.readlines() if line.strip()]
                
                valid_hashes = [h for h in lines if len(h) in [32, 40, 64]]
                if not valid_hashes:
                    print("[-] No valid MD5, SHA-1, or SHA-256 hashes found in the file.")
                    return
                    
                print(f"[*] Found {len(valid_hashes)} valid hashes. Starting Smart Consensus Scan...")
                for h in valid_hashes:
                    print("\n" + "="*50)
                    self.logic.scan_hash(h)
                print(f"\n[+] Batch Hash Scan Complete for: {user_input}")
            except Exception as e:
                print(f"[-] Error reading file: {e}")
                
        # SMART ROUTING: Otherwise, treat it as a single manual hash
        else:
            if len(user_input) not in [32, 40, 64]:
                print(f"[-] Error: Invalid input. Must be a valid .txt file path or a 32/40/64 character hash.")
                return
            self.logic.scan_hash(user_input)

    def _menu_live_edr(self):
        """Routes the live RAM process path into the standard file scanner."""
        target_path = get_target_process_path()
        if target_path:
            print(f"\n[*] Routing live process binary ({target_path}) into analysis pipeline...")
            self.logic.scan_file(target_path)

    def run(self):
        self.print_banner()
        self.setup_api()
        
        while True:
            print("\n" + "="*40)
            print("--- CyberSentinel Menu ---")
            print("="*40)
            print("1. Analyze Local Files & Directories")
            print("2. Query Cloud Threat Intelligence (Hashes)")
            print("3. Scan Active Memory (Live EDR)")
            print("4. Network Containment Management")
            print("5. Settings & Configuration")
            print("6. Exit")
            
            choice = input("\nSelect an option (1-6): ").strip()

            if choice == '1':
                self._continuous_loop(self._menu_analyze_path, "Analyze another path?")
            elif choice == '2':
                self._continuous_loop(self._menu_analyze_hash, "Check another hash/file?")
            elif choice == '3':
                self._continuous_loop(self._menu_live_edr, "Run another Live Memory triage?")
            elif choice == '4':
                from modules import network_isolation
                network_isolation.restore_network()
            elif choice == '5':
                self.update_settings()
            elif choice == '6':
                self.logic.save_session_log()
                print("[*] Exiting CyberSentinel...")
                break
            else:
                print("[-] Invalid choice. Please select 1-6.")
                
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CyberSentinel EDR")
    parser.add_argument("--daemon", help="Run strictly in the background monitoring a specific folder.", type=str, metavar="PATH")
    # NEW ENTERPRISE FLEET COMMAND
    parser.add_argument("--sync", help="Pull enterprise threat intel hashes from a central URL.", type=str, metavar="URL")
    args = parser.parse_args()

    if args.sync:
        print(f"[*] Initiating Fleet Sync from: {args.sync}")
        try:
            import requests
            response = requests.get(args.sync, timeout=10)
            if response.status_code == 200:
                hashes = response.text.splitlines()
                count = 0
                for h in hashes:
                    h = h.strip()
                    if len(h) == 64: # Valid SHA256
                        # Inject directly into the SQLite Cache!
                        utils.save_cached_result(h, "CRITICAL RISK") 
                        count += 1
                print(f"[+] Fleet Sync Complete: {count} enterprise threat signatures added to local DB.")
            else:
                print("[-] Sync failed: Server returned non-200 status.")
        except Exception as e:
            print(f"[-] Network Error during sync: {e}")
            
    elif args.daemon:
        from modules.daemon_monitor import start_daemon
        start_daemon(args.daemon)
    else:
        app = CyberSentinelUI()
        app.run()