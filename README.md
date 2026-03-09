# CyberSentinel: 5-Tiered Enterprise EDR & Malware Analysis Framework

CyberSentinel is an automated, multi-layered Endpoint Detection and Response (EDR) framework built entirely in Python. Designed for under-resourced Security Operations Centers (SOCs) and IT teams, it democratizes enterprise-grade threat intelligence by combining WMI kernel-bridge monitoring, aggregated multi-cloud consensus, offline machine learning, generative AI interpretation, and automated network containment into a single, lightweight command-line utility.

## 🛡️ Enterprise System Architecture
This tool abandons the concept of "single point of failure" scanning. It employs a persistent, 5-tiered detection and mitigation strategy:

* **Tier 0 (Real-Time Intercept):** An autonomous background daemon hooks directly into the Windows Management Instrumentation (WMI) kernel-bridge to intercept and scan processes the exact millisecond they execute in RAM.
* **Tier 1 (Multi-Cloud Consensus):** A Threat Intelligence Multiplexer simultaneously queries a "Smart Consensus" of four global engines (VirusTotal, AlienVault OTX, MetaDefender, and MalwareBazaar) to establish an immediate, zero-trust verdict.
* **Tier 2 (Local Machine Learning):** Extracts Portable Executable (PE) features using `thrember` and analyzes them against a local LightGBM model trained on the EMBER2024 dataset to detect zero-day anomalies without an internet connection.
* **Tier 3 (AI Analyst Interpretation):** Utilizes a locally hosted Ollama LLM (`qwen2.5:3b`) to translate complex behavioral metadata and API calls into human-readable triage reports and actionable YARA rules.
* **Tier 4 (Automated Containment):** Instantly modifies Windows Firewall rules to sever outbound Command and Control (C2) traffic while concurrently dispatching hardware-encrypted JSON telemetry payloads to a SOC Webhook.

## ⚙️ Prerequisites
To run this framework locally, ensure the following are installed and configured:
1. **[Python 3.8+](https://www.python.org/downloads/)** (Must be added to system PATH).
2. **[Ollama](https://ollama.com/)** (Required for the Tier 3 Generative AI Analyst).
3. **API Credentials:** You will need free API keys for [VirusTotal](https://www.virustotal.com/), [AlienVault OTX](https://otx.alienvault.com/), [MetaDefender](https://metadefender.opswat.com/), and an Auth-Key from [MalwareBazaar](https://auth.abuse.ch/).

## 🚀 Installation & Setup

**1. Clone the repository**

git clone https://github.com/JCNA9029/CybersentinelModularized.git

cd CybersentinelModularized

**2. Install Core Python Dependencies**

The easiest way to configure your environment is to double-click the included install.bat file. Alternatively, you can install the complete dependency tree manually using: 

pip install -r requirements.txt

**3. Install the Feature Extractor (Thrember)**

To utilize the offline Machine Learning capabilities, install the EMBER2024 `thrember` feature extractor directly from its source repository:

git clone https://github.com/FutureComputing4AI/EMBER2024.git
cd EMBER2024/
pip install .

**4. Download the Local Machine Learning Models**

Due to GitHub repository size limitations, the compiled LightGBM models are hosted externally. 
* Download the EMBER2024 models from [THIS GOOGLE DRIVE LINK](https://drive.google.com/drive/folders/1dtVVH4Oo5RhoAiMPhqsB4T1X2dGX0v5N?usp=drive_link).
* Place the entire `models/` directory directly into your root `CybersentinelModularized/` folder.

**5. Initialize the AI Analyst**

Install Ollama via the Windows command line, ensure it is running in the background, and pull the required Qwen model:
winget install -e --id Ollama.Ollama
ollama run qwen2.5:3b

## 💻 Usage Instructions

CyberSentinel features a dynamic architecture with three distinct operational modes.

### Mode 1: Interactive Triage (Standard CLI)
Launch the interactive terminal. This mode features "Smart Input Routing"—simply drag and drop a single file, an entire batch directory, a raw hash, or a `.txt` file full of IOCs, and the framework will automatically route it to the correct scanning pipeline.

python CyberSentinel.py

*(Note: On first boot, navigate to Option 5 (Settings) to input your API keys and Discord SOC Webhook URL. These are encrypted locally via a hardware-bound XOR/Base64 cipher.)*

### Mode 2: Enterprise Daemon (Real-Time Protection)
Deploy CyberSentinel as an autonomous background agent. It actively hooks into Windows WMI to monitor process creation and watches a specified directory for dropped files. Threats are auto-quarantined and the network is isolated instantly.
*(Must be run as **Administrator** to allow WMI hooking and Network Containment.)*

python CyberSentinel.py --daemon C:\Path\To\Your\Directory

### Mode 3: Fleet Intelligence Sync
Pull enterprise threat intel hashes (Indicators of Compromise) from a central company server or text file URL and inject them directly into your local offline SQLite cache.

python CyberSentinel.py --sync https://your-company-server.com/latest_threats.txt

### 🛡️ High-Availability / Anti-Tamper Mode
To run the daemon with survivability protections, right-click **`TamperGuard.bat`** and select **Run as Administrator**. If advanced malware attempts to terminate the Python process, the out-of-process heartbeat monitor will instantly resurrect the EDR.

## 📂 Project Structure
* `CyberSentinel.py` - Main CLI interface, smart routing logic, and argument parser.
* `install.bat` / `TamperGuard.bat` - Deployment and survivability scripts.
* `exclusions.txt` - Enterprise allowlist for authorized business applications (auto-generated).
* `modules/` - Core logic package containing:
  * `analysis_manager.py` - Threat detection routing and pipeline execution.
  * `scanner_api.py` - Tier 1 Cloud Intelligence wrappers.
  * `daemon_monitor.py` - WMI kernel-bridge and directory watchdog threads.
  * `network_isolation.py` - Automated firewall containment protocols.
  * `ml_engine.py` - Feature extraction and LightGBM model execution.
  * `live_edr.py` - Live memory triage and process mapping.
  * `utils.py` - SQLite caching, hardware cryptography, and webhooks.

## ⚠️ Disclaimer
CyberSentinel dynamically modifies the Windows Firewall during containment events and interacts deeply with active system memory. It is strictly recommended to test this framework in a sandboxed environment or virtual machine before deploying it to production corporate assets.

## 📞 Contact 
For project inquiries, architecture discussions, or bug reports, contact me on Discord: **@JCNA9029**
