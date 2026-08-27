import time
import pandas as pd
import plotly.express as px
import streamlit as st
from src.database.db import get_connection
from src.capture.traffic_generator import create_synthetic_flow
from src.detection.detection_engine import analyze_and_record_flow

st.set_page_config(page_title="AI Hybrid IDS/IPS", layout="wide")

st.title("🛡️ AI-Powered Hybrid IDS/IPS Console")
st.caption("Live Traffic Analysis • Dual-Engine ML (XGBoost + Isolation Forest) • Automated IPS Response")

# --- Sidebar Controls ---
st.sidebar.header("🕹️ Threat Simulation")
st.sidebar.markdown("Inject controlled traffic to demonstrate detection:")

col_b1, col_b2 = st.sidebar.columns(2)
if col_b1.button("Inject Normal"):
    flow = create_synthetic_flow("Normal")
    analyze_and_record_flow(flow)
    st.sidebar.success("Normal flow generated")

if col_b2.button("Inject DDoS"):
    flow = create_synthetic_flow("DDoS")
    analyze_and_record_flow(flow)
    st.sidebar.error("DDoS attack simulated")

col_b3, col_b4 = st.sidebar.columns(2)
if col_b3.button("Inject Port Scan"):
    flow = create_synthetic_flow("Port Scan")
    analyze_and_record_flow(flow)
    st.sidebar.warning("Port Scan simulated")

if col_b4.button("Inject Brute Force"):
    flow = create_synthetic_flow("Brute Force")
    analyze_and_record_flow(flow)
    st.sidebar.warning("Brute Force simulated")

# --- Query Database ---
conn = get_connection()
df_flows = pd.read_sql_query("SELECT * FROM flow_events ORDER BY id DESC LIMIT 100", conn)
df_blocked = pd.read_sql_query("SELECT * FROM blocked_sources ORDER BY id DESC", conn)
conn.close()

# --- Top Metric Cards ---
total_flows = len(df_flows)
threats = len(df_flows[df_flows["ml_prediction"] != "Normal"]) if total_flows > 0 else 0
anomalies = len(df_flows[df_flows["anomaly_score"] > 0.6]) if total_flows > 0 else 0
blocked_count = len(df_blocked)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Flows Analyzed", total_flows)
m2.metric("Threats Flagged", threats)
m3.metric("Anomalies Detected", anomalies)
m4.metric("Active Blocked IPs", blocked_count)

st.markdown("---")

# --- Visualizations ---
col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("Recent Network Flow Events")
    if not df_flows.empty:
        display_cols = [
            "timestamp", "source_ip", "destination_port", "protocol",
            "ml_prediction", "risk_score", "severity", "action"
        ]
        
        def highlight_severity(val):
            if val == "CRITICAL":
                return "background-color: #ff4d4d; color: white"
            elif val == "HIGH":
                return "background-color: #ffa64d; color: black"
            elif val == "MEDIUM":
                return "background-color: #ffff80; color: black"
            return ""

        styled_df = df_flows[display_cols].head(15).style.map(highlight_severity, subset=["severity"])
        st.dataframe(styled_df, use_container_width=True)
    else:
        st.info("No flow records in database yet. Use the sidebar buttons or start the traffic generator.")

with col_right:
    st.subheader("Attack Distribution")
    if not df_flows.empty and threats > 0:
        attack_counts = df_flows[df_flows["ml_prediction"] != "Normal"]["ml_prediction"].value_counts().reset_index()
        attack_counts.columns = ["Attack Type", "Count"]
        fig = px.pie(attack_counts, names="Attack Type", values="Count", hole=0.4,
                     color_discrete_sequence=px.colors.sequential.RdBu)
        fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=250)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.write("No threats recorded yet.")

# --- Blocked Sources Table ---
st.markdown("---")
st.subheader("🚫 Automated IPS Blocklist")
if not df_blocked.empty:
    st.table(df_blocked[["source_ip", "reason", "risk_score", "blocked_at", "status"]])
else:
    st.caption("No sources currently blocked.")