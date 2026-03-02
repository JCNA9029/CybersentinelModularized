import os
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
        """Allows the user to change or clear their saved API key."""
        print("\n--- Settings: Update API Key ---")
        print("Note: Right-click to paste your new key into the terminal.")
        new_key = input("Enter new VirusTotal API Key (leave blank to clear saved key): ").strip()
        
        self.logic.api_key = new_key if new_key else None
        self.logic.headers["x-apikey"] = new_key if new_key else ""
        utils.save_config(new_key)
        
        if new_key:
            print("[+] API Key updated and saved successfully.")
        else:
            print("[+] API Key cleared. VirusTotal scanning is now disabled.")

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
            print("4. Settings (Update API Key)")
            print("5. Exit")
            choice = input("Select an option (1-5): ").strip()

            if choice == '1':
                file_path = utils.sanitize_path(input("Drag and drop the file you want to scan (or press Enter to cancel): "))
                if file_path and os.path.exists(file_path):
                    self.logic.scan_file(file_path)
                elif not file_path:
                    continue
                else:
                    print("[-] Invalid file path.")
            elif choice == '2':
                if not self.logic.api_key:
                    print("[-] Hash scanning requires a VirusTotal API key.")
                    continue
                # Added a cancel option here for better User Experience
                raw_hash = input("Input the SHA256 (or press Enter to cancel): ").strip()
                # If the user just presses Enter, kick them back to the main menu
                if not raw_hash:
                    continue    
                sha_hash = utils.sanitize_path(raw_hash)
                # Validate the hash before wasting an API call
                if len(sha_hash) not in [32, 40, 64]:
                    print(f"[-] Error: Invalid hash length ({len(sha_hash)} chars).")
                    continue
                self.logic.query_virustotal(sha_hash)
            elif choice == '3':
                self.batch_scan()
            elif choice == '4':
                self.update_settings()
            elif choice == '5':
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