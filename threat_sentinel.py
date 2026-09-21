import os
import socket
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Project Directories
LOGS_DIR = "Security_Logs"
REPORTS_DIR = "Threat_Reports"

# Critical Ports to Monitor
TARGET_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Remote Access)",
    80: "HTTP (Web Service)",
    443: "HTTPS (Secure Web)",
    3389: "RDP (Remote Desktop)",
    3306: "MySQL Database"
}

def setup_environment():
    """Create directory structure for SOC operations"""
    for folder in [LOGS_DIR, REPORTS_DIR]:
        if not os.path.exists(folder):
            os.makedirs(folder)

def scan_single_port(ip, port):
    """Scan port for open service Exposure"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            return port, TARGET_PORTS.get(port, "Unknown"), "EXPOSED"
    except Exception:
        pass
    return port, None, "CLOSED"

def vulnerability_scan(target_ip):
    """Run Port & Service Vulnerability Scan"""
    print(f"\n[+] Executing Vulnerability Assessment on: {target_ip}")
    exposed_services = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_single_port, target_ip, port) for port in TARGET_PORTS.keys()]
        for future in futures:
            port, service, status = future.result()
            if status == "EXPOSED":
                print(f" [!] EXPOSURE DETECTED: Port {port} ({service}) is Open!")
                exposed_services.append({"port": port, "service": service})
            else:
                print(f" [-] Port {port}: Secure (Closed)")

    return exposed_services

def simulate_log_analysis():
    """Analyze system logs for Brute-Force / Intrusion Attacks"""
    print("\n[+] Analyzing Security Logs for Suspicious Activity...")
    
    # Dummy Auth Log creation to simulate real SIEM log parsing
    sample_logs = [
        "192.168.1.50 - SSH Failed Login Attempt (User: root)",
        "192.168.1.50 - SSH Failed Login Attempt (User: root)",
        "192.168.1.50 - SSH Failed Login Attempt (User: admin)",
        "10.0.0.12 - Successful Login (User: user1)",
        "192.168.1.50 - SSH Failed Login Attempt (User: root)"
    ]

    failed_attempts = {}
    threats_found = []

    for log in sample_logs:
        if "Failed Login" in log:
            ip = log.split(" - ")[0]
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    for ip, count in failed_attempts.items():
        if count >= 3:
            threat_msg = f"POSSIBLE BRUTE-FORCE ATTACK: {count} Failed Attempts from IP {ip}"
            print(f" [ALERT] {threat_msg}")
            threats_found.append({"ip": ip, "type": "Brute-Force", "count": count})

    return threats_found

def generate_threat_intelligence_report(target_ip, open_ports, threat_alerts):
    """Generate Final Threat Intelligence & SOC Incident Report"""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = os.path.join(REPORTS_DIR, f"threat_report_{timestamp}.json")

    report_data = {
        "metadata": {
            "tool": "ThreatSentinel v1.0",
            "timestamp": str(datetime.now()),
            "target_scanned": target_ip
        },
        "vulnerability_assessment": {
            "exposed_ports_count": len(open_ports),
            "exposed_services": open_ports
        },
        "log_analysis_incident_response": {
            "threats_detected_count": len(threat_alerts),
            "threat_alerts": threat_alerts
        },
        "risk_score": "HIGH" if (len(open_ports) > 2 or len(threat_alerts) > 0) else "LOW"
    }

    with open(report_filename, "w") as f:
        json.dump(report_data, f, indent=4)

    print("\n" + "="*50)
    print(f"[✔] THREAT INTELLIGENCE ASSESSMENT COMPLETED")
    print(f"[✔] Risk Assessment Score: {report_data['risk_score']}")
    print(f"[✔] Final SOC Incident Report Saved: '{report_filename}'")
    print("="*50)

if __name__ == "__main__":
    setup_environment()
    print("==================================================")
    print("   THREAT SENTINEL - CYBERSECURITY SIEM & SCANNER ")
    print("==================================================")

    target = input("\nEnter Target IP to Scan (Default: 127.0.0.1): ").strip()
    if not target:
        target = "127.0.0.1"

    ports_found = vulnerability_scan(target)
    threats_detected = simulate_log_analysis()
    generate_threat_intelligence_report(target, ports_found, threats_detected)
    