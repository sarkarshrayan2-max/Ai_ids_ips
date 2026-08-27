import joblib
import numpy as np
import pandas as pd
from src.database.db import get_connection
from src.detection.risk_engine import compute_risk

xgb = joblib.load("models/xgboost_model.pkl")
iso_forest = joblib.load("models/isolation_forest.pkl")
scaler = joblib.load("models/scaler.pkl")
label_encoder = joblib.load("models/label_encoder.pkl")

FEATURES = [
    "destination_port", "duration", "packet_count", 
    "byte_count", "packets_per_sec", "bytes_per_sec", "protocol_tcp"
]

def analyze_and_record_flow(flow: dict) -> dict:

    df_feat = pd.DataFrame([flow])[FEATURES]
    feat_scaled = scaler.transform(df_feat)
    

    probs = xgb.predict_proba(feat_scaled)[0]
    pred_idx = np.argmax(probs)
    ml_prediction = label_encoder.inverse_transform([pred_idx])[0]
    ml_confidence = float(probs[pred_idx])
    raw_anomaly = iso_forest.score_samples(feat_scaled)[0]

    anomaly_score_norm = float(np.clip((0.0 - raw_anomaly) / 0.5, 0.0, 1.0))
    

    risk_score, severity, action = compute_risk(ml_prediction, ml_confidence, anomaly_score_norm)
    

    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO flow_events (
            source_ip, destination_ip, source_port, destination_port,
            protocol, duration, packet_count, byte_count,
            packets_per_sec, bytes_per_sec, ml_prediction,
            ml_confidence, anomaly_score, risk_score, severity, action
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        flow["source_ip"], flow["destination_ip"], flow["source_port"], flow["destination_port"],
        flow["protocol"], flow["duration"], flow["packet_count"], flow["byte_count"],
        flow["packets_per_sec"], flow["bytes_per_sec"], ml_prediction,
        ml_confidence, anomaly_score_norm, risk_score, severity, action
    ))
    
    if action == "CONTROLLED BLOCK":
        cursor.execute("""
            INSERT OR IGNORE INTO blocked_sources (source_ip, reason, risk_score)
            VALUES (?, ?, ?)
        """, (flow["source_ip"], f"Classified {ml_prediction} with risk {risk_score}", risk_score))
        
    conn.commit()
    conn.close()
    
    return {
        "source_ip": flow["source_ip"],
        "prediction": ml_prediction,
        "confidence": round(ml_confidence, 2),
        "anomaly_score": round(anomaly_score_norm, 2),
        "risk_score": risk_score,
        "severity": severity,
        "action": action
    }