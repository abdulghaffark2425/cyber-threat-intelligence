import streamlit as st
import json
import os
import pandas as pd

st.set_page_config(page_title="SOC Threat Sentinel Dashboard", layout="wide")

st.title("🛡️ SOC Threat Sentinel - Incident & Defense Dashboard")
st.markdown("Real-time Cyber Threat Intelligence, Log Analysis & Automated Mitigation")

REPORTS_DIR = "Threat_Reports"

def load_latest_report():
    if not os.path.exists(REPORTS_DIR):
        return None
    files = [os.path.join(REPORTS_DIR, f) for f in os.listdir(REPORTS_DIR) if f.endswith('.json')]
    if not files:
        return None
    latest_file = max(files, key=os.path.getmtime)
    with open(latest_file, "r") as f:
        return json.load(f), latest_file

report_data, file_path = load_latest_report() or (None, None)

if report_data:
    st.sidebar.success(f"Loaded Report:\n{os.path.basename(file_path)}")

    col1, col2, col3 = st.columns(3)
    risk_score = report_data["risk_score"]

    col1.metric("Overall Risk Score", risk_score)
    col2.metric("Exposed Ports Found", report_data["vulnerability_assessment"]["exposed_ports_count"])
    col3.metric("Active Threat Alerts", report_data["log_analysis_incident_response"]["threats_detected_count"])

    st.divider()

    st.subheader("⚠️ Detected Threat Alerts & Mitigation Action")
    threats = report_data["log_analysis_incident_response"]["threat_alerts"]

    if threats:
        for threat in threats:
            st.error(f"**ATTACK DETECTED:** {threat['type']} from IP `{threat['ip']}` ({threat['count']} Failed Attempts)")
            st.warning(f"🔒 **Automated Action Taken:** IP `{threat['ip']}` has been added to System Firewall Blacklist Rule!")
    else:
        st.success("No active brute-force threats detected in analyzed logs.")

    st.divider()

    st.subheader("🔍 Port Exposure Breakdown")
    exposed = report_data["vulnerability_assessment"]["exposed_services"]
    if exposed:
        df = pd.DataFrame(exposed)
        st.table(df)
    else:
        st.info("All scanned critical ports are SECURE (Closed).")

else:
    st.warning("No Threat Report found. Run 'python threat_sentinel.py' first to generate data.")