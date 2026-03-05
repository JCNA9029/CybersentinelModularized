import os
import time
from modules import ScannerLogic, utils

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
        # 1. Try to load the saved key first
        saved_key = utils.load_config()
        
        if saved_key:
            self.logic.api_key = saved_key
            self.logic.headers["x-apikey"] = saved_key
            print("[+] Welcome back! Loaded saved VirusTotal API Key.")
        else:
            # 2. If no key is found, do the First-Time Setup
            print("\n--- First Time Setup ---")
            key = input("Enter your VirusTotal API Key (leave blank to skip VT): ").strip()
            
            if key:
                self.logic.api_key = key
                self.logic.headers["x-apikey"] = key
                utils.save_config(key) # Save it for next time!
                self.logic.log_event("[+] API Key saved successfully for future use.")
            else:
                self.logic.log_event("\n[!] Running in Local Machine Learning Mode only.")
    
    def update_settings(self):
        """Allows the user to change or clear their saved API key with built-in safeguards."""
        print("\n--- Settings: Update API Key ---")
        
        # Show the user their current state so they aren't guessing
        current_status = "Active/Saved" if self.logic.api_key else "Not Set"
        print(f"[*] Current API Key Status: {current_status}")
        print("Note: Right-click to paste your new key into the terminal.")
        
        # The new, explicit prompt
        new_key = input("Enter new API Key (Type 'CLEAR' to remove, or press Enter to cancel): ").strip()
        
        # 1. The Escape Hatch (User just pressed Enter)
        if not new_key:
            print("[*] Update cancelled. Existing settings remain unchanged.")
            return # Safely exit the function without touching the saved configuration
            
        # 2. Explicit Deletion
        if new_key.upper() == 'CLEAR':
            self.logic.api_key = None
            self.logic.headers["x-apikey"] = ""
            utils.save_config("") # Overwrite the config with a blank string
            print("[+] API Key cleared. VirusTotal scanning is now disabled.")
            return
            
        # 3. Standard Update
        self.logic.api_key = new_key
        self.logic.headers["x-apikey"] = new_key
        utils.save_config(new_key)
        print("[+] API Key updated and saved successfully.")

    def batch_scan(self):
        if not self.logic.api_key:
            print("[-] Batch hash scanning requires a VirusTotal API key.")
            return
            
        file_path = utils.sanitize_path(input("Drag and drop the .txt file containing the SHA256 hashes: "))
        if not os.path.exists(file_path) or not file_path.lower().endswith('.txt'):
            print("[-] Invalid file. Please provide a valid .txt file.")
            return
            
        show_details = input("Include detailed AV engine results for each hash? (Y/N): ").strip().lower() == 'y'
            
        try:
            with open(file_path, 'r') as f:
                hashes = [line.strip() for line in f if line.strip()]
                
            print(f"\n[*] Starting batch scan for {len(hashes)} hashes...")
            print("[*] Note: To respect cloud API rate limits, scans will pause for 15 seconds between hashes.")
            
            for index, h in enumerate(hashes):
                self.logic.log_event("-" * 60)
                self.logic.log_event(f"[*] Checking hash {index + 1}/{len(hashes)}: {h}")
                self.logic.query_virustotal(h, force_details=show_details, is_batch=True)
                
                # Prevent Rate Limiting (4 requests per minute)
                if index < len(hashes) - 1:
                    time.sleep(15)

            for h in hashes:
                # --- ADD THE SEPARATOR HERE ---
                self.logic.log_event("-" * 60)
                
                self.logic.log_event(f"[*] Checking hash: {h}")
                self.logic.query_virustotal(h, force_details=show_details, is_batch=True)

            self.logic.log_event("\n[*] Batch scan completed.")
                
        except Exception as e:
            print(f"[-] Error reading batch file: {e}")

    def run(self):
        self.print_banner()
        self.setup_api()
        
        while True:
            print("\n--- CyberSentinel Menu ---")
            print("1. Scan a local file")
            print("2. Scan a specific SHA256 Hash")
            print("3. Batch scan a list of hashes (.txt)")
            print("4. Scan Active Running Processes (Live EDR)")
            print("5. Settings (Update API Key)")
            print("6. Exit")
            choice = input("Select an option (1-6): ").strip()

            if choice == '1':
                while True:
                    file_path = utils.sanitize_path(input("\nDrag and drop the file you want to scan (or press Enter to cancel): "))
                    if not file_path: 
                        break # User pressed Enter, back to main menu
                    
                    if os.path.exists(file_path):
                        self.logic.scan_file(file_path)
                    else:
                        print("[-] Invalid file path.")
                        
                    # The QoL Prompt
                    if input("\n[?] Do you want to scan another local file? (Y to continue / Any other key for Menu): ").strip().upper() != 'Y':
                        break

            elif choice == '2':
                if not self.logic.api_key:
                    print("[-] Hash scanning requires a VirusTotal API key.")
                    continue
                    
                while True:
                    raw_hash = input("\nInput the SHA256 (or press Enter to cancel): ").strip()
                    if not raw_hash: 
                        break    
                    
                    sha_hash = utils.sanitize_path(raw_hash)
                    if len(sha_hash) not in [32, 40, 64]:
                        print(f"[-] Error: Invalid hash length ({len(sha_hash)} chars).")
                    else:
                        self.logic.query_virustotal(sha_hash)
                        
                    # The QoL Prompt
                    if input("\n[?] Do you want to check another hash? (Y to continue / Any other key for Menu): ").strip().upper() != 'Y':
                        break

            elif choice == '3':
                while True:
                    self.batch_scan()
                    # The QoL Prompt
                    if input("\n[?] Do you want to run another batch scan? (Y to continue / Any other key for Menu): ").strip().upper() != 'Y':
                        break

            elif choice == '4':
                while True:
                    self.logic.scan_active_processes()
                    # The QoL Prompt
                    if input("\n[?] Do you want to scan another active process? (Y to continue / Any other key for Menu): ").strip().upper() != 'Y':
                        break

            elif choice == '5':
                self.update_settings()
                
            elif choice == '6':
                self.logic.exit_program()
                
            else:
                print("[-] Invalid selection.")

if __name__ == "__main__":
    if utils.check_internet():
        print("[*] Internet connected. Proceeding...")
    else:
        print("[!] No internet connection. VirusTotal will be disabled.")
    
    app = CyberSentinelUI()
    app.run()