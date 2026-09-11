from __future__ import annotations

import json
from pathlib import Path
import sys

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.capture.traffic_generator import (
    create_synthetic_flow,
    run_attack_burst,
)
from src.database.db import (
    get_connection,
    init_db,
)
from src.detection.detection_engine import (
    analyze_and_record_flow,
)
from src.detection.explainability import (
    explain_flow,
)
from src.detection.incident_engine import (
    close_incident,
)
from src.security.ips_controller import (
    IPSController,
)

init_db()

st.set_page_config(
    page_title="AI Sentinel | SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1rem;
        padding-bottom: 1rem;
        max-width: 100%;
    }

    footer {
        visibility: hidden;
    }

    [data-testid="stMetricValue"] {
        font-size: 1.45rem;
    }

    .status-card {
        border: 1px solid rgba(128, 128, 128, 0.25);
        border-radius: 10px;
        padding: 14px 16px;
        min-height: 105px;
    }

    .status-title {
        font-size: 0.85rem;
        font-weight: 600;
        opacity: 0.75;
        margin-bottom: 5px;
    }

    .status-value {
        font-size: 1.1rem;
        font-weight: 700;
    }

    .status-detail {
        font-size: 0.78rem;
        opacity: 0.65;
        margin-top: 4px;
    }

    .section-note {
        font-size: 0.82rem;
        opacity: 0.7;
        margin-top: -8px;
        margin-bottom: 10px;
    }

    .risk-critical {
        font-weight: 700;
    }

    .attack-chain {
        font-size: 1rem;
        font-weight: 600;
        padding: 8px 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def inject_single(kind):
    flow = create_synthetic_flow(kind)
    result = analyze_and_record_flow(flow)
    st.session_state["last_result"] = result
    st.rerun()


def inject_burst(kind, count):
    results = run_attack_burst(
        kind,
        count,
    )
    if results:
        st.session_state["last_result"] = results[-1]
    st.rerun()


def clear_database():
    conn = get_connection()
    conn.execute("DELETE FROM flow_events")
    conn.execute("DELETE FROM incidents")
    conn.execute("DELETE FROM blocked_sources")
    conn.commit()
    conn.close()


def load_json(path):
    if not path.exists():
        return None
    try:
        return json.loads(
            path.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, OSError):
        return None


def metric_value(data, *keys, default=None):
    if not data:
        return default
    for key in keys:
        if key in data:
            return data[key]
    return default


def format_percentage(value):
    if value is None:
        return "N/A"
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "N/A"


def render_status_card(title, value, detail):
    st.markdown(
        f"""
        <div class="status-card">
            <div class="status-title">{title}</div>
            <div class="status-value">{value}</div>
            <div class="status-detail">{detail}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


with st.sidebar:
    st.header("Attack Simulator")
    st.caption(
        "Safe simulation mode. "
        "No host firewall changes are made."
    )

    st.subheader("Single Event")
    for kind in [
        "Normal",
        "DDoS",
        "Port Scan",
        "Brute Force",
    ]:
        if st.button(kind, use_container_width=True):
            inject_single(kind)

    st.divider()

    st.subheader("Attack Burst")
    burst_kind = st.selectbox(
        "Attack Type",
        [
            "DDoS",
            "Port Scan",
            "Brute Force",
        ],
    )

    burst_count = st.slider(
        "Number of flows",
        min_value=1,
        max_value=30,
        value=10,
    )

    if st.button("Run Attack Burst", use_container_width=True):
        inject_burst(burst_kind, burst_count)

    st.divider()

    st.subheader("SOC Controls")
    if st.button("Clear SOC Data", use_container_width=True):
        clear_database()
        st.session_state.pop("last_result", None)
        st.rerun()

    st.divider()
    st.caption(
        "IPS enforcement is intentionally disabled "
        "for this demonstration."
    )


conn = get_connection()

all_flows = pd.read_sql_query(
    """
    SELECT *
    FROM flow_events
    ORDER BY id DESC
    """,
    conn,
)

flows = all_flows.head(150)

blocked = pd.read_sql_query(
    """
    SELECT *
    FROM blocked_sources
    WHERE status='BLOCKED'
    ORDER BY risk_score DESC
    """,
    conn,
)

incidents = pd.read_sql_query(
    """
    SELECT *
    FROM incidents
    ORDER BY
        CASE status
            WHEN 'OPEN' THEN 0
            ELSE 1
        END,
        last_seen DESC
    LIMIT 50
    """,
    conn,
)

conn.close()

metrics_path = ROOT / "models" / "metrics.json"
cic_metrics_path = ROOT / "models" / "cic_metrics.json"

synthetic_metrics = load_json(metrics_path)
cic_metrics = load_json(cic_metrics_path)

st.title("AI Sentinel")
st.caption("Hybrid AI Intrusion Detection and Prevention System")
st.markdown(
    "AI-driven network monitoring combining supervised classification, "
    "unsupervised anomaly detection, behavioral evidence, historical context, "
    "risk fusion, incident correlation, and simulated IPS response."
)

if all_flows.empty:
    threats = 0
    critical = 0
    anomalies = 0
    avg_risk = 0.0
else:
    threats = int((all_flows["ml_prediction"] != "Normal").sum())
    critical = int((all_flows["severity"] == "CRITICAL").sum())
    anomalies = int((all_flows["anomaly_score"] >= 0.5).sum())
    avg_risk = float(all_flows["risk_score"].mean())

open_incidents = (
    int((incidents["status"] == "OPEN").sum()) if not incidents.empty else 0
)
blocked_count = len(blocked)

st.subheader("SOC Overview")
overview_metrics = st.columns(6)

overview_metrics[0].metric("Flows", len(all_flows))
overview_metrics[1].metric("Threats", threats)
overview_metrics[2].metric("Anomalies", anomalies)
overview_metrics[3].metric("Critical", critical)
overview_metrics[4].metric("Open Incidents", open_incidents)
overview_metrics[5].metric("Blocked Sources", blocked_count)

st.divider()

st.subheader("System Status")
status_columns = st.columns(4)

with status_columns[0]:
    render_status_card(
        "Detection Engine",
        "ONLINE",
        "Hybrid ML + anomaly + behavior + history",
    )

with status_columns[1]:
    render_status_card(
        "Database",
        "ONLINE",
        "SQLite event and incident persistence",
    )

with status_columns[2]:
    render_status_card(
        "IPS",
        "SIMULATION",
        "Enforcement disabled; no firewall changes",
    )

with status_columns[3]:
    render_status_card(
        "Live Model",
        "XGBoost",
        "Synthetic traffic demonstration model",
    )

st.divider()

model_left, model_right = st.columns(2)

with model_left:
    st.subheader("Live Detection Model")
    st.markdown(
        """
        **XGBoost classifier**

        The live dashboard simulator uses the synthetic-traffic model.

        **Decision pipeline**

        `XGBoost → Isolation Forest → Behavior → History → Risk Fusion → IPS`
        """
    )

    if synthetic_metrics:
        a, b, c, d = st.columns(4)

        a.metric(
            "Accuracy",
            format_percentage(
                metric_value(
                    synthetic_metrics,
                    "accuracy",
                )
            ),
        )

        b.metric(
            "Precision",
            format_percentage(
                metric_value(
                    synthetic_metrics,
                    "macro_precision",
                    "precision",
                )
            ),
        )

        c.metric(
            "Recall",
            format_percentage(
                metric_value(
                    synthetic_metrics,
                    "macro_recall",
                    "recall",
                )
            ),
        )

        d.metric(
            "Macro F1",
            format_percentage(
                metric_value(
                    synthetic_metrics,
                    "macro_f1",
                    "f1",
                )
            ),
        )

        st.caption(
            "Metrics shown here are from the synthetic hold-out evaluation."
        )
    else:
        st.warning("Synthetic model metrics are unavailable.")

with model_right:
    st.subheader("CIC-IDS2017 Validation")
    st.markdown(
        """
        **Independent real-dataset evaluation**

        CIC-IDS2017 validation is kept separate from the synthetic
        live-demo model to avoid presenting synthetic performance as
        real-world IDS performance.
        """
    )

    if cic_metrics:
        a, b = st.columns(2)
        c, d = st.columns(2)

        a.metric(
            "Accuracy",
            format_percentage(
                metric_value(
                    cic_metrics,
                    "accuracy",
                )
            ),
        )

        b.metric(
            "Macro F1",
            format_percentage(
                metric_value(
                    cic_metrics,
                    "macro_f1",
                    "f1",
                )
            ),
        )

        c.metric(
            "Precision",
            format_percentage(
                metric_value(
                    cic_metrics,
                    "macro_precision",
                    "precision",
                )
            ),
        )

        d.metric(
            "Recall",
            format_percentage(
                metric_value(
                    cic_metrics,
                    "macro_recall",
                    "recall",
                )
            ),
        )

        st.caption(
            "Independent CIC-IDS2017 validation. "
            "Not used as the live synthetic traffic model."
        )
    else:
        st.warning("CIC-IDS2017 validation metrics are unavailable.")

st.divider()

left, right = st.columns([1.45, 1])

with left:
    st.subheader("Live Threat Timeline")
    st.markdown(
        '<div class="section-note">'
        "Risk score over time. Thresholds: 35 = monitor, "
        "65 = high risk, 85 = critical/block."
        "</div>",
        unsafe_allow_html=True,
    )

    if not flows.empty:
        timeline = flows.sort_values("id")

        fig = px.scatter(
            timeline,
            x="timestamp",
            y="risk_score",
            color="severity",
            symbol="ml_prediction",
            hover_data=[
                "source_ip",
                "destination_port",
                "action",
                "incident_id",
            ],
            range_y=[0, 100],
        )

        fig.add_hline(
            y=85,
            line_dash="dash",
            annotation_text="CRITICAL / BLOCK",
        )

        fig.add_hline(
            y=65,
            line_dash="dot",
            annotation_text="HIGH RISK",
        )

        fig.add_hline(
            y=35,
            line_dash="dot",
            annotation_text="MONITOR",
        )

        fig.update_layout(
            height=400,
            margin=dict(l=10, r=10, t=20, b=10),
            legend_title_text="",
        )

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Run an attack scenario from the sidebar.")

with right:
    st.subheader("Threat Distribution")

    if threats:
        counts = (
            all_flows[all_flows["ml_prediction"] != "Normal"]["ml_prediction"]
            .value_counts()
            .rename_axis("Attack")
            .reset_index(name="Count")
        )

        fig = px.pie(
            counts,
            names="Attack",
            values="Count",
            hole=0.55,
        )

        fig.update_layout(
            height=400,
            margin=dict(l=10, r=10, t=20, b=10),
        )

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No threats detected.")

st.subheader("Risk Distribution")

if not flows.empty:
    fig = px.histogram(
        flows,
        x="risk_score",
        nbins=20,
        range_x=[0, 100],
    )

    fig.add_vline(
        x=35,
        line_dash="dot",
        annotation_text="Monitor",
    )

    fig.add_vline(
        x=65,
        line_dash="dot",
        annotation_text="High",
    )

    fig.add_vline(
        x=85,
        line_dash="dash",
        annotation_text="Critical",
    )

    fig.update_layout(
        height=280,
        margin=dict(l=10, r=10, t=10, b=10),
    )

    st.plotly_chart(fig, use_container_width=True)

st.divider()

st.subheader("Incident Correlation")
st.markdown(
    '<div class="section-note">'
    "Events from the same source are correlated into incidents within "
    "the configured detection window."
    "</div>",
    unsafe_allow_html=True,
)

if not incidents.empty:
    incident_display = incidents.copy()

    incident_display["attack_types"] = (
        incident_display["attack_types"]
        .fillna("[]")
        .map(lambda value: " → ".join(json.loads(value)))
    )

    incident_display = incident_display.rename(
        columns={
            "incident_id": "Incident",
            "source_ip": "Source",
            "attack_types": "Attack Chain",
            "event_count": "Events",
            "max_risk": "Risk",
            "first_seen": "First Seen",
            "last_seen": "Last Seen",
            "status": "Status",
            "action": "Action",
        }
    )

    st.dataframe(
        incident_display[
            [
                "Incident",
                "Source",
                "Attack Chain",
                "Events",
                "Risk",
                "Status",
                "Action",
                "First Seen",
                "Last Seen",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    open_incident_rows = incident_display[
        incident_display["Status"] == "OPEN"
    ]

    if not open_incident_rows.empty:
        st.markdown("**Active Attack Chains**")

        for _, row in open_incident_rows.iterrows():
            chain = row["Attack Chain"]

            if chain:
                st.markdown(
                    f"""
                    <div class="attack-chain">
                        {chain}
                        &nbsp; → &nbsp;
                        Risk {row["Risk"]}/100
                        &nbsp; → &nbsp;
                        {row["Action"]}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
else:
    st.caption("No incidents currently correlated.")

st.divider()

events_col, inspector_col = st.columns([1.35, 1])

with events_col:
    st.subheader("Recent Network Events")

    if not flows.empty:
        event_columns = [
            "id",
            "timestamp",
            "source_ip",
            "destination_port",
            "ml_prediction",
            "ml_confidence",
            "anomaly_score",
            "behavior_score",
            "history_score",
            "risk_score",
            "severity",
            "action",
            "incident_id",
        ]

        event_display = flows[event_columns].copy()
        event_display = event_display.rename(
            columns={
                "id": "ID",
                "timestamp": "Timestamp",
                "source_ip": "Source",
                "destination_port": "Dst Port",
                "ml_prediction": "Prediction",
                "ml_confidence": "ML Conf.",
                "anomaly_score": "Anomaly",
                "behavior_score": "Behavior",
                "history_score": "History",
                "risk_score": "Risk",
                "severity": "Severity",
                "action": "Action",
                "incident_id": "Incident",
            }
        )

        st.dataframe(
            event_display,
            use_container_width=True,
            height=420,
            hide_index=True,
        )
    else:
        st.caption("No network events.")

with inspector_col:
    st.subheader("AI Decision Inspector")

    if not flows.empty:
        selected_event = st.selectbox(
            "Select Event",
            flows["id"].tolist(),
        )

        selected = (
            flows[flows["id"] == selected_event]
            .iloc[0]
            .to_dict()
        )

        risk_score = int(selected["risk_score"])

        st.metric(
            "Final Risk Score",
            f"{risk_score}/100",
            selected["severity"],
        )

        c1, c2 = st.columns(2)
        c1.metric("Prediction", selected["ml_prediction"])
        c2.metric("Action", selected["action"])

        c3, c4, c5 = st.columns(3)
        c3.metric("XGBoost", f"{selected['ml_confidence'] * 100:.0f}%")
        c4.metric("Anomaly", f"{selected['anomaly_score']:.2f}")
        c5.metric("Behavior", f"{selected['behavior_score']:.2f}")

        c6, c7 = st.columns(2)
        c6.metric("History", f"{selected['history_score']:.2f}")
        c7.metric("Incident", selected.get("incident_id") or "None")

        st.markdown("**Risk-Fusion Evidence**")

        evidence_df = pd.DataFrame(
            [
                {
                    "Signal": "XGBoost confidence",
                    "Value": f"{selected['ml_confidence']:.3f}",
                },
                {
                    "Signal": "Anomaly score",
                    "Value": f"{selected['anomaly_score']:.3f}",
                },
                {
                    "Signal": "Behavior score",
                    "Value": f"{selected['behavior_score']:.3f}",
                },
                {
                    "Signal": "History score",
                    "Value": f"{selected['history_score']:.3f}",
                },
                {
                    "Signal": "Final risk",
                    "Value": f"{risk_score}/100",
                },
            ]
        )

        st.dataframe(
            evidence_df,
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("**Detection Evidence**")
        for reason in explain_flow(selected):
            st.write(f"• {reason}")
    else:
        st.caption("Select an event after running traffic.")

st.divider()

ips_col, summary_col = st.columns([1.35, 1])

with ips_col:
    st.subheader("IPS Quarantine")
    st.caption(
        "Simulation only. Sources are recorded as blocked in SQLite; "
        "no operating-system firewall rule is modified."
    )

    if not blocked.empty:
        blocked_display = blocked[
            [
                "source_ip",
                "reason",
                "risk_score",
                "blocked_at",
                "status",
            ]
        ].rename(
            columns={
                "source_ip": "Source",
                "reason": "Reason",
                "risk_score": "Risk",
                "blocked_at": "Blocked At",
                "status": "Status",
            }
        )

        st.dataframe(
            blocked_display,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.caption("No sources are currently blocked.")

with summary_col:
    st.subheader("Detection Summary")

    if all_flows.empty:
        st.info("No traffic has been analyzed yet.")
    else:
        normal_count = int(
            (all_flows["ml_prediction"] == "Normal").sum()
        )
        monitored_count = int(
            (all_flows["action"] == "MONITOR").sum()
        )
        alerted_count = int(
            (all_flows["action"] == "ALERT").sum()
        )
        blocked_events = int(
            (all_flows["action"] == "BLOCK").sum()
        )

        a, b = st.columns(2)
        a.metric("Normal", normal_count)
        b.metric("Monitored", monitored_count)

        c, d = st.columns(2)
        c.metric("Alerts", alerted_count)
        d.metric("Block Decisions", blocked_events)

        st.metric(
            "Average Risk",
            f"{avg_risk:.1f}/100",
        )

st.divider()

with st.expander("How AI Sentinel Makes a Decision"):
    st.markdown(
        """
        ### Detection pipeline

        **1. Supervised detection**

        XGBoost classifies the observed network flow.

        **2. Unsupervised detection**

        Isolation Forest evaluates how anomalous the flow is relative
        to learned traffic behavior.

        **3. Behavioral analysis**

        Packet rate, byte rate, ports, duration, and traffic patterns
        contribute independent behavioral evidence.

        **4. Historical context**

        Recent suspicious activity from the same source contributes
        a history signal.

        **5. Risk fusion**

        These signals are combined into a normalized 0–100 risk score.

        **6. Incident correlation**

        Related events from the same source are grouped into an
        incident and attack chain.

        **7. IPS response**

        Critical events generate a block decision. In this project,
        enforcement is deliberately simulated.
        """
    )

if st.session_state.get("last_result"):
    with st.expander("Latest Detection Result", expanded=True):
        result = st.session_state["last_result"]

        st.write(
            f"**{result['prediction']}** | "
            f"Risk **{result['risk_score']}/100** | "
            f"Severity **{result['severity']}** | "
            f"Action **{result['action']}**"
        )

        if result.get("incident_id"):
            st.write(f"Incident: `{result['incident_id']}`")

        if result.get("block_result"):
            st.write(f"IPS: `{result['block_result']}`")

        if result.get("indicators"):
            st.write(
                "**Indicators:** " + ", ".join(result["indicators"])
            )

        st.markdown("**Detection Explanation**")
        for explanation in result.get("explanation", []):
            st.write(f"• {explanation}")

st.caption(
    "AI Sentinel | Hybrid AI IDS/IPS | "
    "Live traffic uses the synthetic demonstration model; "
    "CIC-IDS2017 is reported as independent validation."
)