def compute_risk(ml_prediction: str, ml_confidence: float, anomaly_score_norm: float) -> tuple[int, str, str]:
    """
    Computes a composite risk score (0-100), severity level, and action.
    - ml_prediction: "Normal", "DDoS", "Port Scan", "Brute Force"
    - ml_confidence: Model confidence (0.0 to 1.0)
    - anomaly_score_norm: Normalized anomaly severity (0.0 to 1.0, where 1.0 is highly anomalous)
    """
    severity_weights = {
        "Normal": 0.0,
        "Port Scan": 0.5,
        "Brute Force": 0.7,
        "DDoS": 0.95
    }
    
    base_weight = severity_weights.get(ml_prediction, 0.3)

    risk = (base_weight * ml_confidence * 55) + (anomaly_score_norm * 45)
    risk_score = int(min(max(risk, 0), 100))
    
    if risk_score >= 85:
        severity = "CRITICAL"
        action = "CONTROLLED BLOCK"
    elif risk_score >= 60:
        severity = "HIGH"
        action = "ALERT"
    elif risk_score >= 35:
        severity = "MEDIUM"
        action = "MONITOR"
    else:
        severity = "LOW"
        action = "ALLOW"
        
    return risk_score, severity, action