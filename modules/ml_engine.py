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

class LocalScanner:
    def __init__(self, all_model_path='./models/EMBER2024_ALL.model', family_model_path='./models/EMBER2024_family.model', labels_path='./models/family_labels.json', threshold=0.7):
        self.all_model_path = all_model_path
        self.family_model_path = family_model_path
        self.labels_path = labels_path
        self.threshold = threshold  # 0.7 mitigates false positives on core DLLs
        
        self.all_model = None
        self.family_model = None
        self.family_labels = self.load_labels()

    def load_labels(self):
        """Loads JSON mapping for malware family IDs."""
        if not os.path.exists(self.labels_path):
            return None
        try:
            with open(self.labels_path, 'r') as f:
                return json.load(f)
        except Exception:
            return None

    def load_model(self, path):
        """Loads LightGBM binary trees into memory."""
        if not os.path.exists(path):
            print(f"[-] Model file '{path}' not found.")
            return None
        
        loading_spinner = Spinner(f"[*] Loading Machine Learning Model...")
        loading_spinner.start()
        try:
            model = lgb.Booster(model_file=path)
            loading_spinner.stop() 
            return model       
        except Exception as e:
            loading_spinner.stop()
            print(f"[-] Failed to load ML Model: {e}")
            return None

    def extract_features(self, file_path):
        """Utilizes thrember to map PE structural metadata into a float32 tensor."""
        supported_extensions = ('.exe', '.dll', '.sys', '.apk', '.elf', '.pdf')
        if not file_path.lower().endswith(supported_extensions):
            return None
            
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            extractor = thrember.PEFeatureExtractor()
            features = np.array(extractor.feature_vector(file_data), dtype=np.float32)
            del file_data # Explicitly free memory for large binaries
            return features.reshape(1, -1)
            
        except PermissionError:
            print("\n[!!!] CRITICAL WARNING: Permission Denied [!!!]")
            print("[-] The OS has locked this file. It is ACTIVELY RUNNING in memory.")
            return None
        except Exception:
            return None
        
    def get_suspicious_apis(self, file_path):
        """
        Parses the Import Address Table (IAT) for forensic analysis.
        MEMORY FIX: Utilizes fast_load=True to prevent pefile from crashing 
        system RAM when parsing intentionally malformed malware headers.
        """
        suspicious_calls = []
        target_apis = {
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 
            'SetWindowsHookEx', 'GetKeyboardState', 'URLDownloadToFile',
            'RegSetValueEx', 'CryptEncrypt', 'HttpSendRequest'
        }
        
        try:
            # Only loads standard headers, skipping massive data directories
            pe = pefile.PE(file_path, fast_load=True)
            # Explicitly instruct pefile to only parse the Import directory
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('utf-8')
                            if name in target_apis:
                                suspicious_calls.append(name)
                                
            pe.close() # Free the PE object from memory
            return list(set(suspicious_calls)) 
        except Exception:
            return []

    def scan_stage1(self, file_path):
        """Executes offline ML inference and applies behavioral thresholding."""
        loading_spinner = Spinner(f"[*] Extracting dimensional features...")
        loading_spinner.start()
        features = self.extract_features(file_path)
        loading_spinner.stop()
        
        if features is None:
            return None

        if self.all_model is None:
            self.all_model = self.load_model(self.all_model_path)
            if self.all_model is None: 
                return None
        
        try:
            raw_score = float(self.all_model.predict(features)[0])
            
            # Decision Boundary Ruleset
            if raw_score >= 0.75:
                verdict, is_malicious = "CRITICAL RISK", True
            elif 0.50 <= raw_score < 0.75:
                verdict, is_malicious = "SUSPICIOUS", False 
            else:
                verdict, is_malicious = "SAFE", False
                
            apis = self.get_suspicious_apis(file_path)
            
            return {
                "verdict": verdict,
                "score": raw_score,
                "is_malicious": is_malicious,
                "features": features,
                "detected_apis": apis
            }
        except Exception as e:
            print(f"[-] ML Inference Execution Failed: {e}")
            return None
        
    def scan_stage2(self, features):
        """Executes deep malware family classification."""
        if self.family_model is None:
            print("[*] Loading Malware Family DB...")
            self.family_model = self.load_model(self.family_model_path)
            
        if self.family_model is not None:
            family_probs = self.family_model.predict(features)[0]
            best_match_id = int(np.argmax(family_probs))
            
            fam_name = f"Family ID #{best_match_id}"
            if self.family_labels and isinstance(self.family_labels, dict):
                fam_name = self.family_labels.get(str(best_match_id), fam_name)
                    
            return {"family_name": fam_name, "family_confidence": float(family_probs[best_match_id])}
        return None