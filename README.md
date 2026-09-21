# ??? Threat Sentinel - Mini SIEM & SOC Incident Response Dashboard

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red.svg)
![Security](https://img.shields.io/badge/Cybersecurity-SIEM-green.svg)

**Threat Sentinel** is an automated lightweight Security Information and Event Management (SIEM) tool combined with a real-time Security Operations Center (SOC) dashboard. It performs network port vulnerability scanning, parses incoming log data for brute-force attack patterns, auto-generates JSON incident reports, and visualizes security metrics.

---

## ?? Key Features

- **?? Automated Port & Vulnerability Scanner:** Multi-threaded checks on critical network ports (SSH, HTTP, HTTPS, RDP, MySQL, FTP).
- **?? Log Analysis & Threat Detection:** Automatically parses security logs to detect unauthorized authentication attempts and brute-force attacks.
- **?? Automated Incident Mitigation:** Triggers mock system firewall blacklist rules for attacking IP addresses upon threshold breach.
- **?? Real-time SOC Dashboard:** Visualizes risk metrics, exposed assets, and attack alerts using Streamlit.
- **?? JSON Incident Reporting:** Auto-saves structured incident logs with timestamps and risk severity scores.

---

## ??? Tech Stack & Dependencies

- **Language:** Python
- **UI Framework:** Streamlit
- **Data Handling:** Pandas
- **Standard Libraries:** socket, concurrent.futures, json, os, datetime

---

## ?? Getting Started

### 1. Installation
Clone the repository and install required packages:
\\\ash
git clone https://github.com/abdulghaffark2425/cyber-threat-intelligence.git
cd cyber-threat-intelligence
pip install streamlit pandas
\\\

### 2. Run Threat Engine (SIEM Backend)
Execute the threat assessment scanner to analyze ports, logs, and generate incident reports:
\\\ash
python threat_sentinel.py
\\\

### 3. Launch SOC Dashboard
Launch the visual monitoring dashboard in your browser:
\\\ash
python -m streamlit run dashboard.py
\\\

---

## ?? Dashboard Preview
The dashboard displays:
1. **Overall Risk Score:** (e.g., HIGH / SECURE)
2. **Active Threats:** Attack origins and attempt counts.
3. **Automated Defense Action:** Blacklist confirmation status.
4. **Port Exposure Table:** Detailed breakdown of open/closed critical ports.
