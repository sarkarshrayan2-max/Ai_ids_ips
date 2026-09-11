import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import plotly.express as px
import streamlit as st

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
        font-size: 1.55rem;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


def inject_single(kind):

    flow = create_synthetic_flow(
        kind
    )

    result = analyze_and_record_flow(
        flow
    )

    st.session_state[
        "last_result"
    ] = result

    st.rerun()


def inject_burst(kind, count):

    results = run_attack_burst(
        kind,
        count,
    )

    if results:
        st.session_state[
            "last_result"
        ] = results[-1]

    st.rerun()


def clear_database():

    conn = get_connection()

    conn.execute(
        "DELETE FROM flow_events"
    )

    conn.execute(
        "DELETE FROM incidents"
    )

    conn.execute(
        "DELETE FROM blocked_sources"
    )

    conn.commit()
    conn.close()


with st.sidebar:

    st.header(
        "Attack Simulator"
    )

    st.caption(
        "Safe simulation mode. "
        "No host firewall changes are made."
    )

    st.subheader(
        "Single Event"
    )

    for kind in [
        "Normal",
        "DDoS",
        "Port Scan",
        "Brute Force",
    ]:

        if st.button(
            kind,
            use_container_width=True,
        ):
            inject_single(kind)

    st.divider()

    st.subheader(
        "Attack Burst"
    )

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

    if st.button(
        "Run Attack Burst",
        use_container_width=True,
    ):
        inject_burst(
            burst_kind,
            burst_count,
        )

    st.divider()

    if st.button(
        "Clear SOC Data",
        use_container_width=True,
    ):

        clear_database()

        st.session_state.pop(
            "last_result",
            None,
        )

        st.rerun()


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


st.title(
    "AI Sentinel"
)

st.caption(
    "Hybrid AI Intrusion Detection "
    "and Prevention System"
)


if all_flows.empty:

    threats = 0
    critical = 0
    anomalies = 0
    avg_risk = 0

else:

    threats = int(
        (
            all_flows[
                "ml_prediction"
            ] != "Normal"
        ).sum()
    )

    critical = int(
        (
            all_flows[
                "severity"
            ] == "CRITICAL"
        ).sum()
    )

    anomalies = int(
        (
            all_flows[
                "anomaly_score"
            ] >= 0.5
        ).sum()
    )

    avg_risk = float(
        all_flows[
            "risk_score"
        ].mean()
    )


open_incidents = (
    int(
        (
            incidents[
                "status"
            ] == "OPEN"
        ).sum()
    )
    if not incidents.empty
    else 0
)


blocked_count = (
    len(blocked)
)


metrics = st.columns(6)

metrics[0].metric(
    "Flows",
    len(all_flows),
)

metrics[1].metric(
    "Threats",
    threats,
)

metrics[2].metric(
    "Anomalies",
    anomalies,
)

metrics[3].metric(
    "Critical",
    critical,
)

metrics[4].metric(
    "Open Incidents",
    open_incidents,
)

metrics[5].metric(
    "Blocked Sources",
    blocked_count,
)


st.divider()


left, right = st.columns(
    [1.4, 1]
)


with left:

    st.subheader(
        "Live Threat Timeline"
    )

    if not flows.empty:

        timeline = (
            flows
            .sort_values("id")
        )

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
            range_y=[
                0,
                100,
            ],
        )

        fig.add_hline(
            y=85,
            line_dash="dash",
            annotation_text="AUTO-BLOCK",
        )

        fig.add_hline(
            y=65,
            line_dash="dot",
            annotation_text="HIGH RISK",
        )

        fig.update_layout(
            height=380,
            margin=dict(
                l=10,
                r=10,
                t=20,
                b=10,
            ),
            legend_title_text="",
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    else:

        st.info(
            "Run an attack scenario "
            "from the sidebar."
        )


with right:

    st.subheader(
        "Threat Distribution"
    )

    if threats:

        counts = (
            all_flows[
                all_flows[
                    "ml_prediction"
                ] != "Normal"
            ][
                "ml_prediction"
            ]
            .value_counts()
            .rename_axis("Attack")
            .reset_index(
                name="Count"
            )
        )

        fig = px.pie(
            counts,
            names="Attack",
            values="Count",
            hole=0.55,
        )

        fig.update_layout(
            height=380,
            margin=dict(
                l=10,
                r=10,
                t=20,
                b=10,
            ),
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    else:

        st.info(
            "No threats detected."
        )


st.subheader(
    "Risk Distribution"
)

if not flows.empty:

    fig = px.histogram(
        flows,
        x="risk_score",
        nbins=20,
        range_x=[
            0,
            100,
        ],
    )

    fig.update_layout(
        height=280,
        margin=dict(
            l=10,
            r=10,
            t=10,
            b=10,
        ),
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
    )


st.subheader(
    "Active Incidents"
)


if not incidents.empty:

    incident_display = incidents.copy()

    incident_display[
        "attack_types"
    ] = (
        incident_display[
            "attack_types"
        ]
        .fillna("[]")
        .map(
            lambda value:
                " → ".join(
                    json.loads(value)
                )
        )
    )

    incident_display = (
        incident_display.rename(
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

else:

    st.caption(
        "No incidents currently correlated."
    )


st.divider()


events_col, inspector_col = st.columns(
    [1.35, 1]
)


with events_col:

    st.subheader(
        "Recent Network Events"
    )

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

        st.dataframe(
            flows[
                event_columns
            ],
            use_container_width=True,
            height=400,
            hide_index=True,
        )

    else:

        st.caption(
            "No network events."
        )


with inspector_col:

    st.subheader(
        "AI Decision Inspector"
    )

    if not flows.empty:

        selected_event = st.selectbox(
            "Select Event",
            flows["id"].tolist(),
        )

        selected = (
            flows[
                flows["id"]
                == selected_event
            ]
            .iloc[0]
            .to_dict()
        )

        st.metric(
            "Risk Score",
            f"{selected['risk_score']}/100",
            selected["severity"],
        )

        c1, c2, c3 = st.columns(3)

        c1.metric(
            "XGBoost",
            f"{selected['ml_confidence'] * 100:.0f}%",
        )

        c2.metric(
            "Anomaly",
            f"{selected['anomaly_score']:.2f}",
        )

        c3.metric(
            "Behavior",
            f"{selected['behavior_score']:.2f}",
        )

        c4, c5 = st.columns(2)

        c4.metric(
            "History",
            f"{selected['history_score']:.2f}",
        )

        c5.metric(
            "Prediction",
            selected["ml_prediction"],
        )

        st.markdown(
            f"**Action:** `{selected['action']}`"
        )

        st.markdown(
            f"**Incident:** "
            f"`{selected.get('incident_id') or 'None'}`"
        )

        st.markdown(
            "**Detection Evidence**"
        )

        for reason in explain_flow(
            selected
        ):

            st.write(
                f"• {reason}"
            )

    else:

        st.caption(
            "Select an event after "
            "running traffic."
        )


st.subheader(
    "IPS Quarantine"
)

if not blocked.empty:

    st.dataframe(
        blocked[
            [
                "source_ip",
                "reason",
                "risk_score",
                "blocked_at",
                "status",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

else:

    st.caption(
        "No sources are currently blocked."
    )


with st.expander(
    "Model Validation"
):

    metrics_path = (
        ROOT
        / "models"
        / "metrics.json"
    )

    if metrics_path.exists():

        model_metrics = json.loads(
            metrics_path.read_text()
        )

        a, b, c, d = st.columns(4)

        a.metric(
            "Accuracy",
            f"{model_metrics['accuracy'] * 100:.1f}%",
        )

        b.metric(
            "Precision",
            f"{model_metrics['macro_precision'] * 100:.1f}%",
        )

        c.metric(
            "Recall",
            f"{model_metrics['macro_recall'] * 100:.1f}%",
        )

        d.metric(
            "Macro F1",
            f"{model_metrics['macro_f1'] * 100:.1f}%",
        )

        st.warning(
            "These metrics are from the synthetic "
            "hold-out dataset. Real-world IDS performance "
            "must be evaluated separately."
        )

    else:

        st.warning(
            "Model metrics are unavailable. "
            "Run the training pipeline."
        )


if st.session_state.get(
    "last_result"
):

    with st.expander(
        "Latest Detection Result",
        expanded=True,
    ):

        result = st.session_state[
            "last_result"
        ]

        st.write(
            f"**{result['prediction']}** | "
            f"Risk **{result['risk_score']}/100** | "
            f"Action **{result['action']}**"
        )

        if result.get(
            "incident_id"
        ):

            st.write(
                f"Incident: "
                f"`{result['incident_id']}`"
            )

        if result.get(
            "block_result"
        ):

            st.write(
                f"IPS: "
                f"`{result['block_result']}`"
            )

        for explanation in result.get(
            "explanation",
            [],
        ):

            st.write(
                f"• {explanation}"
            )