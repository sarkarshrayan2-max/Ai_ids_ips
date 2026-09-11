from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.database.db import get_connection, init_db
from src.detection.explainability import explain_flow
from src.detection.incident_engine import correlate_incident
from src.detection.risk_engine import (
    compute_behavior_score,
    compute_risk,
)
from src.security.ips_controller import IPSController


ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = ROOT / "models"

xgb = joblib.load(
    MODEL_DIR / "xgboost_model.pkl"
)

iso_forest = joblib.load(
    MODEL_DIR / "isolation_forest.pkl"
)

scaler = joblib.load(
    MODEL_DIR / "scaler.pkl"
)

label_encoder = joblib.load(
    MODEL_DIR / "label_encoder.pkl"
)


FEATURES = [
    "destination_port",
    "duration",
    "packet_count",
    "byte_count",
    "packets_per_sec",
    "bytes_per_sec",
    "protocol_tcp",
]


ips_controller = IPSController(
    enforcement_mode=False
)


def _calculate_history_score(source_ip: str) -> float:

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            COUNT(*) AS suspicious_count,
            MAX(risk_score) AS max_risk
        FROM flow_events
        WHERE source_ip=?
          AND risk_score>=35
          AND datetime(timestamp) >= datetime('now', '-10 minutes')
        """,
        (source_ip,),
    ).fetchone()

    conn.close()

    count = int(row["suspicious_count"] or 0)
    max_risk = int(row["max_risk"] or 0)

    count_signal = min(count / 10.0, 1.0)
    risk_signal = max_risk / 100.0

    return round(
        min(
            1.0,
            count_signal * 0.6 + risk_signal * 0.4
        ),
        3,
    )


def analyze_and_record_flow(flow: dict) -> dict:

    init_db()

    df_features = pd.DataFrame(
        [flow]
    )[FEATURES]

    scaled_features = scaler.transform(
        df_features
    )

    probabilities = xgb.predict_proba(
        scaled_features
    )[0]

    prediction_index = int(
        np.argmax(probabilities)
    )

    ml_prediction = label_encoder.inverse_transform(
        [prediction_index]
    )[0]

    ml_confidence = float(
        probabilities[prediction_index]
    )

    raw_anomaly = float(
        iso_forest.score_samples(
            scaled_features
        )[0]
    )

    anomaly_score = float(
        np.clip(
            (0.0 - raw_anomaly) / 0.5,
            0.0,
            1.0,
        )
    )

    behavior_score, indicators = (
        compute_behavior_score(flow)
    )

    history_score = _calculate_history_score(
        flow["source_ip"]
    )

    risk_score, severity, action = compute_risk(
        ml_prediction,
        ml_confidence,
        anomaly_score,
        behavior_score,
        history_score,
    )

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO flow_events (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            duration,
            packet_count,
            byte_count,
            packets_per_sec,
            bytes_per_sec,
            protocol_tcp,
            ml_prediction,
            ml_confidence,
            anomaly_score,
            behavior_score,
            history_score,
            risk_score,
            severity,
            action
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            flow["source_ip"],
            flow["destination_ip"],
            flow["source_port"],
            flow["destination_port"],
            flow["protocol"],
            flow["duration"],
            flow["packet_count"],
            flow["byte_count"],
            flow["packets_per_sec"],
            flow["bytes_per_sec"],
            flow.get("protocol_tcp", 0),
            ml_prediction,
            ml_confidence,
            anomaly_score,
            behavior_score,
            history_score,
            risk_score,
            severity,
            action,
        ),
    )

    event_id = cursor.lastrowid

    conn.commit()
    conn.close()

    incident_id = correlate_incident(
        flow["source_ip"],
        ml_prediction,
        risk_score,
        action,
    )

    block_result = None

    if action == "BLOCK":

        block_result = ips_controller.block_ip(
            source_ip=flow["source_ip"],
            reason=(
                f"{ml_prediction}; "
                f"risk={risk_score}; "
                f"indicators="
                f"{', '.join(indicators) or 'model consensus'}"
            ),
            risk_score=risk_score,
        )

    conn = get_connection()

    conn.execute(
        """
        UPDATE flow_events
        SET incident_id=?
        WHERE id=?
        """,
        (
            incident_id,
            event_id,
        ),
    )

    conn.commit()
    conn.close()

    result = {
        "event_id": event_id,
        "source_ip": flow["source_ip"],
        "destination_ip": flow["destination_ip"],
        "prediction": ml_prediction,
        "confidence": round(
            ml_confidence,
            3,
        ),
        "anomaly_score": round(
            anomaly_score,
            3,
        ),
        "behavior_score": round(
            behavior_score,
            3,
        ),
        "history_score": round(
            history_score,
            3,
        ),
        "risk_score": risk_score,
        "severity": severity,
        "action": action,
        "incident_id": incident_id,
        "indicators": indicators,
        "block_result": block_result,
    }

    result["explanation"] = explain_flow(
        {
            **flow,
            "ml_prediction": ml_prediction,
            "ml_confidence": ml_confidence,
            "anomaly_score": anomaly_score,
            "behavior_score": behavior_score,
            "history_score": history_score,
        }
    )

    return result