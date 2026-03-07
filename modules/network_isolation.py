import subprocess
import ctypes
import os

def is_admin():
    """Checks if the Python script has Windows Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def isolate_network():
    """
    Drops the Windows Firewall guillotine. 
    Blocks all inbound and outbound traffic to stop data exfiltration and C2 communication.
    """
    if not is_admin():
        print("\n[-] ISOLATION FAILED: Administrator privileges required.")
        print("[-] To enable Automated Network Containment, run your terminal as Administrator.")
        return False

    try:
        print("[*] Engaging Network Containment Protocol...")
        # Modifies the firewall to block everything
        subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"], 
            check=True, capture_output=True, text=True
        )
        print("[+] SUCCESS: Host isolated. All outbound network traffic is now blocked.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Firewall modification failed: {e}")
        return False

def restore_network():
    """
    The Escape Hatch. Restores the Windows Firewall back to its default state
    (Block Inbound, Allow Outbound).
    """
    if not is_admin():
        print("\n[-] RESTORE FAILED: Administrator privileges required.")
        return False

    try:
        subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"], 
            check=True, capture_output=True, text=True
        )
        print("[+] SUCCESS: Network connectivity restored to default state.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Firewall modification failed: {e}")
        return False