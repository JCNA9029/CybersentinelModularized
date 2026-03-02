# CyberSentinel: Multi-Tiered Malware Analysis Framework (UNDER CONSTRUCTION)

CyberSentinel is an automated, multi-layered malware analysis CLI tool designed to identify and explain potential threats using collective intelligence, local machine learning, and generative AI.

## 🛡️ System Architecture
This tool employs a three-tiered detection strategy:
* **Tier 1 (Cloud Intelligence):** Queries the VirusTotal API to check file hashes against global antivirus engines.
* **Tier 2 (Local Machine Learning):** Extracts Portable Executable (PE) features using `thrember` and analyzes them against a LightGBM model trained on the EMBER2024 dataset. Automatically bypasses files over 50MB to preserve system resources.
* **Tier 3 (AI Analyst Interpretation):** Utilizes a local Ollama LLM (`llama3:8b`) to generate human-readable threat reports and mitigation strategies based on identified malware families and imported APIs.

## ⚙️ Prerequisites
To run this program locally, you must have the following installed:
1. [Python 3.8+](https://www.python.org/downloads/)
2. [Ollama Desktop](https://ollama.com/) (Required for the Tier 3 AI Analyst)

## 🚀 Installation & Setup

**1. Clone the repository**

git clone [https://github.com/YOUR_USERNAME/CyberSentinel2026.git](https://github.com/YOUR_USERNAME/CyberSentinel2026.git)
cd CyberSentinel2026

**2. Install Python dependencies**
pip install -r requirements.txt

**3. Initialize the AI Analyst (Ollama)**
Ensure the Ollama desktop app is running in the background, then pull the required model:
ollama run llama3:8b

*(Note: If the models/ directory is not included in this repository due to size limits, please download the EMBER2024 models from [HERE](https://drive.google.com/drive/folders/1dtVVH4Oo5RhoAiMPhqsB4T1X2dGX0v5N?usp=drive_link) and place it in the root directory).*

## 💻 Usage
Run the main interface from your terminal:
python CyberSentinel2026.py

On the first boot, the program will prompt you for a VirusTotal API key. This key will be encrypted via XOR/Base64 and stored locally in a config.json file for future sessions.

## 📂 Project Structure
CyberSentinel2026.py - Main CLI interface and entry point.

modules/ - Core logic package containing:

analysis_manager.py - Threat detection routing, API calls, and report generation.

ml_engine.py - Feature extraction and LightGBM model execution.

utils.py - Configuration management and cryptography.

loading.py - Terminal UI elements.

## 📞 Contact 
If found any problems contact me on Discord: @JCNA9029 
