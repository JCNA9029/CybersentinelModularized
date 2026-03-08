import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .analysis_manager import ScannerLogic

# --- 1. The Existing Folder Watcher ---
class ThreatHandler(FileSystemEventHandler):
    def __init__(self, logic_instance):
        self.logic = logic_instance

    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith(('.exe', '.dll', '.sys', '.apk', '.elf', '.pdf')):
            print(f"\n[DAEMON] 🚨 File drop intercepted: {event.src_path}")
            time.sleep(2) # Wait for OS transfer
            try:
                self.logic.scan_file(event.src_path)
            except Exception as e:
                pass

# --- 2. WMI HOOK ---
def monitor_process_execution(logic_instance):
    """Hooks into Windows WMI to catch processes the millisecond they execute."""
    try:
        import wmi
        import pythoncom
        pythoncom.CoInitialize() # Required for WMI threading
        
        c = wmi.WMI()
        # Subscribe to process creation events natively from the Windows Kernel
        process_watcher = c.Win32_Process.watch_for("creation")
        
        while True:
            new_process = process_watcher()
            exe_path = new_process.ExecutablePath
            
            # BLUE TEAM SAFEGUARD: Ignore standard Windows OS files (Fixed Case-Sensitivity)
            if exe_path and "c:\\windows" not in exe_path.lower():
                print(f"\n[DAEMON] ⚙️ Execution Intercepted: {new_process.Name} (PID: {new_process.ProcessId})")
                try:
                    logic_instance.scan_file(exe_path)
                except Exception as e:
                    # Print a tiny warning instead of failing completely silently
                    print(f"[-] Scanner bypassed {new_process.Name} (Likely locked by OS permissions)")
                    
    # THIS is the line that accidentally got deleted!
    except Exception as e:
        print(f"[-] WMI Hook Failed: {e}")

# --- 3. The Dual-Threaded Starter ---
def start_daemon(target_dir):
    logic = ScannerLogic()
    logic.headless_mode = True 

    print(f"\n[+] CyberSentinel Headless Daemon Active.")
    print(f"[*] 📂 Watching directory: {os.path.abspath(target_dir)}")
    print(f"[*] ⚙️  WMI Kernel-Bridge Hook Active (Watching RAM for executions)")
    
    # Start the WMI hook on a background thread so it doesn't block the folder watcher
    wmi_thread = threading.Thread(target=monitor_process_execution, args=(logic,), daemon=True)
    wmi_thread.start()

    # Start the folder watcher on the main thread
    if os.path.exists(target_dir):
        event_handler = ThreatHandler(logic)
        observer = Observer()
        observer.schedule(event_handler, target_dir, recursive=False)
        observer.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            print("\n[*] Daemon shutting down...")
        observer.join()
    else:
        # NEW: Tell the user they messed up the path!
        print(f"\n[-] CRITICAL ERROR: The folder '{target_dir}' does not exist!")
        print("[-] Please create the folder or update your TamperGuard.bat file.")
        time.sleep(5) # Pause so you can read the error before the batch file restarts it