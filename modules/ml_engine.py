import json
import os
import numpy as np
import pefile
import lightgbm as lgb
from .loading import Spinner

try:
    import thrember
except ImportError:
    print("[!] Warning: 'thrember' library not found. Local ML scanning will fail.")
    print("    Install via: pip install git+https://github.com/FutureComputing4AI/EMBER2024.git")

class LocalScanner:
    def __init__(self, all_model_path='./models/EMBER2024_all.model', family_model_path='./models/EMBER2024_family.model', labels_path='./models/family_labels.json', threshold=0.5):
        self.all_model_path = all_model_path
        self.family_model_path = family_model_path
        self.labels_path = labels_path
        self.threshold = threshold
        
        self.all_model = None
        self.family_model = None
        self.family_labels = self.load_labels()

    def load_labels(self):
        if not os.path.exists(self.labels_path):
            return None
        try:
            with open(self.labels_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[-] Failed to read labels JSON: {e}")
            return None

    def load_model(self, path):
        if not os.path.exists(path):
            print(f"[-] Model file '{path}' not found.")
            return None
        
        # Start the spinner before the heavy loading begins
        loading_spinner = Spinner(f"[*] Loading Malware Detection Dataset...")
        loading_spinner.start()
        
        try:
            model = lgb.Booster(model_file=path)
            loading_spinner.stop() # Stop immediately once done
            print(f"[+] Malware Detection Dataset loaded successfully.")
            return model       
        except Exception as e:
            loading_spinner.stop()
            print(f"[-] Failed to load {path}: {e}")
            return None

    def extract_features(self, file_path):
        supported_extensions = ('.exe', '.dll', '.sys', '.apk', '.elf', '.pdf')
        if not file_path.lower().endswith(supported_extensions):
            print(f"[-] File type not supported. Supported: {supported_extensions}")
            return None
            
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            extractor = thrember.PEFeatureExtractor()
            features = np.array(extractor.feature_vector(file_data), dtype=np.float32)
            return features.reshape(1, -1)
        except Exception as e:
            print(f"[-] Extraction error: {e}")
            return None
        
    def get_suspicious_apis(self, file_path):
        """Extracts interesting Windows API calls for the LLM to analyze."""
        suspicious_calls = []
        # A small sample of APIs that LLMs can reason about effectively
        target_apis = {
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 
            'SetWindowsHookEx', 'GetKeyboardState', 'URLDownloadToFile',
            'RegSetValueEx', 'CryptEncrypt', 'HttpSendRequest'
        }
        
        try:
            #looking if the file has PE attribute (Windows Executable: .exe, .dll, .sys)
            pe = pefile.PE(file_path)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('utf-8')
                            if name in target_apis:
                                suspicious_calls.append(name)
            return list(set(suspicious_calls)) # Unique calls only
        except:
            return []

    def scan_stage1(self, file_path):
        """Runs the lightweight detection model and returns the features for reuse."""
        loading_spinner = Spinner(f"[*] Extracting features...")
        loading_spinner.start()
        features = self.extract_features(file_path)
        loading_spinner.stop()
        
        if features is None:
            return None

        if self.all_model is None:
            self.all_model = self.load_model(self.all_model_path)
            if self.all_model is None: 
                
                return None
        score = self.all_model.predict(features)[0]
        is_malicious = score > self.threshold
       

        apis = self.get_suspicious_apis(file_path)
        return {
            "score": float(score),
            "is_malicious": is_malicious,
            "features": features,
            "detected_apis": apis
        }

    def scan_stage2(self, features):
        """Loads the heavy family model only when explicitly called."""
        if self.family_model is None:
            print("[*] Loading Malware Family Data into memory... (This takes a moment)")
            self.family_model = self.load_model(self.family_model_path)
            
        if self.family_model is not None:
            family_probs = self.family_model.predict(features)[0]
            best_match_id = int(np.argmax(family_probs))
            confidence = float(family_probs[best_match_id])
            
            fam_name = f"Family ID #{best_match_id}"
            
            if self.family_labels:
                if isinstance(self.family_labels, dict):
                    fam_name = self.family_labels.get(str(best_match_id), fam_name)
                elif isinstance(self.family_labels, list) and best_match_id < len(self.family_labels):
                    fam_name = self.family_labels[best_match_id]
                    
            return {
                "family_name": fam_name,
                "family_confidence": confidence
            }
    
        return None