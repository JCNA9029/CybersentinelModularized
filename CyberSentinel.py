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
        saved_key = config.get("api_key", "")
        self.logic.webhook_url = config.get("webhook_url", "")
        
        if saved_key:
            self.logic.api_key = saved_key
            print("[+] Welcome back! Loaded saved Configuration.")
        else:
            print("\n--- First Time Setup ---")
            key = input("Enter your VirusTotal API Key (leave blank to skip VT): ").strip()
            if key:
                self.logic.api_key = key
                utils.save_config(key, self.logic.webhook_url)
                self.logic.log_event("[+] API Key saved successfully for future use.")
            else:
                self.logic.log_event("\n[!] Running in Local Machine Learning Mode only.")

    def update_settings(self):
        """Exposed API and Webhook configuration interface."""
        print("\n--- Settings: Update Configuration ---")
        
        # 1. API Key Setup
        current_api = "Active/Saved" if self.logic.api_key else "Not Set"
        print(f"[*] Current API Key Status: {current_api}")
        new_key = input("Enter new API Key (Type 'CLEAR' to remove, or press Enter to keep current): ").strip()
        
        if new_key.upper() == 'CLEAR':
            self.logic.api_key = None
            new_key = ""
            print("[+] API Key cleared. Cloud scanning disabled.")
        elif not new_key:
            new_key = self.logic.api_key # Keep existing
            
        # 2. Webhook Setup
        current_webhook = "Active/Saved" if self.logic.webhook_url else "Not Set"
        print(f"\n[*] Current Webhook Status: {current_webhook}")
        new_webhook = input("Enter new Webhook URL (Type 'CLEAR' to remove, or press Enter to keep current): ").strip()
        
        if new_webhook.upper() == 'CLEAR':
            self.logic.webhook_url = ""
            print("[+] Webhook cleared. SOC alerting disabled.")
        elif new_webhook:
            self.logic.webhook_url = new_webhook
        else:
            new_webhook = self.logic.webhook_url # Keep existing
            
        # Save both parameters simultaneously
        utils.save_config(new_key or "", self.logic.webhook_url)
        print("[+] Configuration updated successfully.")
    def _continuous_loop(self, action_func, prompt_msg):
        """Helper abstraction to keep the user in a continuous workflow."""
        while True:
            action_func()
            if input(f"\n[?] {prompt_msg} (Y to continue / Any other key for Menu): ").strip().upper() != 'Y':
                break

    def _menu_scan_file(self):
        file_path = utils.sanitize_path(input("\nDrag and drop the file to scan (or press Enter to cancel): "))
        if file_path and os.path.exists(file_path):
            self.logic.scan_file(file_path)
        elif file_path:
            print("[-] Invalid physical file path.")

    def _menu_scan_hash(self):
        if not self.logic.api_key:
            print("[-] Hash scanning requires a VirusTotal API key.")
            return
            
        raw_hash = input("\nInput the SHA256 (or press Enter to cancel): ").strip()
        if not raw_hash: 
            return
            
        sha_hash = utils.sanitize_path(raw_hash)
        if len(sha_hash) not in [32, 40, 64]:
            print(f"[-] Error: Invalid hash length ({len(sha_hash)} chars).")
        else:
            vt_api = VirusTotalAPI(self.logic.api_key)
            result = vt_api.query_hash(sha_hash)
            print(f"[*] Cloud Result: {result.get('verdict', result.get('message'))}")

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
            print("\n--- CyberSentinel Menu ---")
            print("1. Scan a local file")
            print("2. Scan a specific SHA256 Hash")
            print("3. Scan Active Running Processes (Live EDR)")
            print("4. Settings (Update API Key / Webhook)")
            print("5. Restore Network Access (Disable Isolation)")
            print("6. Exit")
            choice = input("Select an option (1-6): ").strip()

            if choice == '1':
                self._continuous_loop(self._menu_scan_file, "Scan another local file?")
            elif choice == '2':
                self._continuous_loop(self._menu_scan_hash, "Check another hash?")
            elif choice == '3':
                self._continuous_loop(self._menu_live_edr, "Scan another active process?")
            elif choice == '4':
                self.update_settings()
            elif choice == '5':
                restore_network()
            elif choice == '6':
                self.logic.save_session_log()
                print("Exiting. Stay secure!")
                sys.exit()
            else:
                print("[-] Invalid selection.")

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