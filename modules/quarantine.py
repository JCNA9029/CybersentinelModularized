import os
import shutil

def quarantine_file(file_path, quarantine_dir="./quarantine_zone"):
    """
    Safely moves and neutralizes a malicious file by altering its extension.
    Requires user authorization before execution.
    """
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
        # Optional: Hide the folder in Windows so users don't poke around
        # os.system(f'attrib +h "{quarantine_dir}"')

    try:
        filename = os.path.basename(file_path)
        # Neutralize the file so it cannot execute
        safe_filename = filename + ".quarantine"
        destination = os.path.join(quarantine_dir, safe_filename)

        # Move the file out of the user's reach
        shutil.move(file_path, destination)
        
        print("\n" + "="*50)
        print(f"[+] SUCCESS: Threat securely quarantined.")
        print(f"[*] Original File: {filename}")
        print(f"[*] Secure Location: {destination}")
        print("="*50 + "\n")
        return True
        
    except PermissionError:
        print("\n[-] ACTION FAILED: Permission denied.")
        print("[-] The malware might currently be running in the background.")
        print("[-] Please run CyberSentinel as Administrator to force quarantine.\n")
        return False
    except Exception as e:
        print(f"\n[-] ACTION FAILED: {e}\n")
        return False