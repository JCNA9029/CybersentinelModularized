# The Main UI of the Program
# Handles the user interface, input validation, and routes commands to the ScannerLogic module. 
# Also manages API key configuration and session logging.
import argparse
import os
import ctypes
import tkinter as tk
from tkinter import filedialog
from modules import ScannerLogic, utils
from modules.live_edr import get_target_process_path
from modules.network_isolation import isolate_network, restore_network

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
        self.logic.api_keys = config.get("api_keys", {})
        self.logic.webhook_url = config.get("webhook_url", "")
        
        if self.logic.api_keys:
            print("[+] Configuration Loaded: Multi-Cloud Intelligence Active.")
        else:
            print("\n--- First Time Setup ---")
            key = input("Enter your VirusTotal API Key (leave blank to skip VT): ").strip()
            if key:
                self.logic.api_keys["virustotal"] = key
                utils.save_config(self.logic.api_keys, self.logic.webhook_url)
                self.logic.log_event("[+] API Key saved successfully.")
            else:
                self.logic.log_event("\n[!] Operating in Offline Mode: Local ML Engine Only.")

    def update_settings(self):
        """Exposed API and Webhook configuration interface."""
        print("\n--- Settings: Multi-Cloud Configuration ---")
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
            
        utils.save_config(self.logic.api_keys, self.logic.webhook_url)
        print("[+] Global Configuration updated successfully.")

    def _menu_view_cache(self):
        """Dumps the local SQLite threat cache to the terminal."""
        print("\n--- Local Threat Intelligence Cache ---")
        try:
            import sqlite3
            with sqlite3.connect("threat_cache.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT sha256, filename, verdict, timestamp FROM scan_cache")
                rows = cursor.fetchall()
                if not rows:
                    print("[*] The cache is currently empty.")
                    return
                print(f"{'SHA-256 Hash':<64} | {'File Name':<20} | {'Verdict':<15} | {'Timestamp'}")
                print("-" * 130)
                for row in rows:
                    fname = (row[1][:17] + '...') if row[1] and len(row[1]) > 20 else str(row[1])
                    print(f"{row[0]:<64} | {fname:<20} | {row[2]:<15} | {row[3]}")
        except sqlite3.Error as e:
            print(f"[-] Database Error: {e}")

    def _menu_network_containment(self):
        """Interactive sub-menu for explicit network isolation control."""
        print("\n--- Network Containment Management ---")
        print("1. ISOLATE HOST (Block all inbound/outbound traffic)")
        print("2. RESTORE NETWORK (Return firewall to enterprise default)")
        print("3. Cancel")
        
        choice = input("\nSelect action (1-3): ").strip()
        if choice == '1':
            isolate_network()
        elif choice == '2':
            restore_network()
        else:
            print("[*] Action cancelled.")

    def _menu_analyze_path(self):
        """Prompts the user for a target and handles both single files and batch directories."""
        print("\n" + "="*50)
        target = input("Enter File or Directory path (or press Enter to open File Picker): ").strip()
        target = target.strip('\"').strip('\'')
        
        # 1. Native Windows GUI Fallback for Empty Input
        if not target:
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except AttributeError:
                is_admin = False
                
            if is_admin:
                print("[*] Administrator mode detected. Launching UIPI bypass file picker...")
                root = tk.Tk()
                root.withdraw() 
                root.attributes('-topmost', True) 
                target = filedialog.askopenfilename(title="CyberSentinel: Select File to Scan")
                if not target:
                    print("[-] File selection cancelled.")
                    return
            else:
                print("[-] No path provided. Scan cancelled.")
                return

        # 2. Directory Batch Scanning Logic
        if os.path.isdir(target):
            print(f"[*] Directory detected. Initiating batch scan of {target}...")
            file_count = 0
            for root, _, files in os.walk(target):
                for file in files:
                    file_path = os.path.join(root, file)
                    # We only send potential executables to the routing manager to save time
                    if file_path.lower().endswith(('.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.bin', '.tmp')):
                        self.logic.scan_file(file_path)
                        file_count += 1
            print(f"\n[+] Directory Batch Scan Complete. Analyzed {file_count} potential PE files.")
        
        # 3. Single File Scanning Logic
        elif os.path.isfile(target):
            self.logic.scan_file(target)
        else:
            print(f"[-] Error: '{target}' is not a valid file or directory path.")

    def _menu_analyze_hash(self):
        """Intelligently handles both single hashes and batch .txt files."""
        print("\n" + "="*50)
        user_input = input("Paste a Hash OR path to a .txt IoC file (Enter to cancel): ").strip().strip('"').strip("'")
        if not user_input: return
            
        if os.path.isfile(user_input) and user_input.endswith('.txt'):
            print(f"\n[*] Reading IoC file: {user_input}")
            try:
                with open(user_input, 'r', encoding='utf-8') as f:
                    lines = [line.strip() for line in f.readlines() if line.strip()]
                valid_hashes = [h for h in lines if len(h) in [32, 40, 64]]
                if not valid_hashes:
                    print("[-] No valid hashes found in the file.")
                    return
                print(f"[*] Found {len(valid_hashes)} valid hashes. Starting Smart Consensus Scan...")
                for h in valid_hashes:
                    print("\n" + "-"*30)
                    self.logic.scan_hash(h)
                print(f"\n[+] Batch Hash Scan Complete for: {user_input}")
            except Exception as e:
                print(f"[-] Error reading file: {e}")
        else:
            if len(user_input) not in [32, 40, 64]:
                print("[-] Error: Invalid input. Must be a .txt path or a 32/40/64 character hash.")
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
            print("\n" + "="*45)
            print("         CyberSentinel App CLI")
            print("="*45)
            print(" 1. Scan Local File or Directory")
            print(" 2. Scan Hash or IoC Batch List")
            print(" 3. Analyze Active Memory (Live EDR)")
            print(" 4. Network Containment Management")
            print(" 5. Configure Cloud Integrations")
            print(" 6. View Local Threat Cache")
            print(" 7. Generate Report & Exit")
            print("="*45)
            
            choice = input("\nSelect a command [1-7]: ").strip()

            if choice == '1':
                self._menu_analyze_path()
                input("\nPress Enter to return to menu...")
            elif choice == '2':
                self._menu_analyze_hash()
                input("\nPress Enter to return to menu...")
            elif choice == '3':
                self._menu_live_edr()
                input("\nPress Enter to return to menu...")
            elif choice == '4':
                self._menu_network_containment()
                input("\nPress Enter to return to menu...")
            elif choice == '5':
                self.update_settings()
                input("\nPress Enter to return to menu...")
            elif choice == '6':
                self._menu_view_cache()
                input("\nPress Enter to return to menu...")
            elif choice == '7':
                self.logic.save_session_log()
                print("[*] Terminating CyberSentinel interface...")
                break
            else:
                print("[-] Command not recognized.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSentinel Multi-Tiered EDR Engine")
    parser.add_argument("--daemon", help="Run strictly in the background monitoring a specific folder.", type=str, metavar="PATH")
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
                    if len(h) == 64: 
                        utils.save_cached_result(h, "CRITICAL RISK", "Fleet Sync") 
                        count += 1
                print(f"[+] Fleet Sync Complete: {count} enterprise threat signatures added to local cache.")
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