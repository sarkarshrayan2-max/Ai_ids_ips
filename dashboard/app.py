import pandas as pd
import plotly.express as px
import streamlit as st

from src.capture.traffic_generator import create_synthetic_flow
from src.database.db import get_connection
from src.detection.detection_engine import analyze_and_record_flow
from src.detection.explainability import explain_flow

st.set_page_config(page_title="AI Hybrid IDS/IPS", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
    /* Minimize margins and padding for no-scroll single-screen view */
    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 0rem !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        max-width: 100% !important;
    }
    header, footer {visibility: hidden !important;}
    h1, h2, h3, h4, h5, h6 {
        margin-top: 0.1rem !important;
        margin-bottom: 0.3rem !important;
        padding: 0 !important;
    }
    [data-testid="stMetricValue"] {
        font-size: 1.5rem !important;
    }
    [data-testid="stMetricLabel"] {
        font-size: 0.8rem !important;
    }
    .metric-container {
        background-color: #1a1c24;
        border-radius: 6px;
        padding: 6px 12px;
        border: 1px solid #2e3440;
    }
    .stSelectbox, .stButton {
        margin-bottom: 0px !important;
    }
    div[data-testid="stExpander"] {
        margin-top: 0.2rem !important;
    }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.subheader("🕹️ Simulation Controls")
    
    col_b1, col_b2 = st.columns(2)
    if col_b1.button("Normal", use_container_width=True):
        flow = create_synthetic_flow("Normal")
        analyze_and_record_flow(flow)
        st.rerun()

    if col_b2.button("DDoS", use_container_width=True):
        flow = create_synthetic_flow("DDoS")
        analyze_and_record_flow(flow)
        st.rerun()

    col_b3, col_b4 = st.columns(2)
    if col_b3.button("Port Scan", use_container_width=True):
        flow = create_synthetic_flow("Port Scan")
        analyze_and_record_flow(flow)
        st.rerun()

    if col_b4.button("Brute Force", use_container_width=True):
        flow = create_synthetic_flow("Brute Force")
        analyze_and_record_flow(flow)
        st.rerun()

    st.markdown("---")
    if st.button("🧹 Clear Logs", use_container_width=True):
        conn = get_connection()
        conn.execute("DELETE FROM flow_events")
        conn.execute("DELETE FROM blocked_sources")
        conn.commit()
        conn.close()
        st.rerun()

conn = get_connection()
df_flows = pd.read_sql_query("SELECT * FROM flow_events ORDER BY id DESC LIMIT 50", conn)
df_blocked = pd.read_sql_query("SELECT * FROM blocked_sources ORDER BY id DESC LIMIT 20", conn)
conn.close()

st.markdown("### 🛡️ AI-Powered Hybrid IDS/IPS Console")

total_flows = len(df_flows)
threats = len(df_flows[df_flows["ml_prediction"] != "Normal"]) if total_flows > 0 else 0
anomalies = len(df_flows[df_flows["anomaly_score"] >= 0.5]) if total_flows > 0 else 0
blocked_count = len(df_blocked)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Flows Analyzed", total_flows)
m2.metric("Threats Flagged", threats)
m3.metric("Anomalies Detected", anomalies)
m4.metric("Active Blocklist", blocked_count)

st.markdown("<hr style='margin: 0.4rem 0;'>", unsafe_allow_html=True)

col_main_left, col_main_right = st.columns([1.3, 1.0], gap="medium")

with col_main_left:
    st.markdown("##### 📡 Live Network Flows (Latest 50)")
    if not df_flows.empty:
        display_cols = [
            "id", "source_ip", "destination_port", "protocol",
            "ml_prediction", "risk_score", "severity", "action"
        ]
        def highlight_severity(val):
            if val == "CRITICAL":
                return "background-color: #8b0000; color: white"
            elif val == "HIGH":
                return "background-color: #b35900; color: white"
            elif val == "MEDIUM":
                return "background-color: #737300; color: white"
            elif val == "LOW":
                return "background-color: #005926; color: white"
            return ""

        styled_df = df_flows[display_cols].style.map(highlight_severity, subset=["severity"])
        st.dataframe(styled_df, height=210, use_container_width=True)
    else:
        st.info("No flow data. Inject traffic via the sidebar.", icon="ℹ️")

    st.markdown("##### 🚫 Automated IPS Quarantine List")
    if not df_blocked.empty:
        st.dataframe(df_blocked[["id", "source_ip", "reason", "risk_score", "blocked_at", "status"]], height=130, use_container_width=True)
    else:
        st.caption("No sources currently quarantined.")


with col_main_right:
   
    st.markdown("##### 📊 Threat Profile")
    if not df_flows.empty and threats > 0:
        attack_counts = df_flows[df_flows["ml_prediction"] != "Normal"]["ml_prediction"].value_counts().reset_index()
        attack_counts.columns = ["Attack Type", "Count"]
        fig = px.pie(
            attack_counts, names="Attack Type", values="Count", hole=0.5,
            color_discrete_sequence=px.colors.sequential.RdBu
        )
        fig.update_layout(
            margin=dict(t=5, b=5, l=10, r=10),
            height=140,
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5)
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("Clean traffic baseline. No active attacks detected.")

    st.markdown("##### 🔍 Forensics & Explainability Inspector")
    if not df_flows.empty:
        selected_id = st.selectbox("Inspect Event ID:", df_flows["id"].tolist(), label_visibility="collapsed")
        flow_row = df_flows[df_flows["id"] == selected_id].iloc[0].to_dict()
        
        info_col1, info_col2 = st.columns(2)
        with info_col1:
            st.markdown(f"**Class:** `{flow_row['ml_prediction']}` ({flow_row['ml_confidence']*100:.0f}%)")
            st.markdown(f"**Anomaly:** `{flow_row['anomaly_score']:.2f}`")
        with info_col2:
            st.markdown(f"**Risk Score:** `{flow_row['risk_score']}/100`")
            st.markdown(f"**Action:** `{flow_row['action']}`")
            
        explanations = explain_flow(flow_row)
        for exp in explanations[:3]:
            st.markdown(f"<small>{exp}</small>", unsafe_allow_html=True)
    else:
        st.caption("Generate events to view model explanations.")