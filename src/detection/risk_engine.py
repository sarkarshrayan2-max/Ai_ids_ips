from __future__ import annotations

ATTACK_WEIGHTS = {
    "Normal": 0.00,
    "Port Scan": 0.62,
    "Brute Force": 0.78,
    "DDoS": 0.95,
}


def compute_behavior_score(flow: dict) -> tuple[float, list[str]]:
    score = 0.0
    indicators = []

    pps = float(flow.get("packets_per_sec", 0))
    bps = float(flow.get("bytes_per_sec", 0))
    duration = float(flow.get("duration", 0))
    packets = int(flow.get("packet_count", 0))
    port = int(flow.get("destination_port", 0))

    if pps >= 5000:
        score += 0.45
        indicators.append("Extreme packet-rate surge")
    elif pps >= 2000:
        score += 0.30
        indicators.append("High packet-rate surge")
    elif pps >= 500:
        score += 0.12
        indicators.append("Elevated packet rate")

    if bps >= 5_000_000:
        score += 0.20
        indicators.append("High bandwidth utilization")
    elif bps >= 1_000_000:
        score += 0.10
        indicators.append("Elevated bandwidth utilization")

    if packets <= 5 and duration < 0.1 and port > 1024:
        score += 0.28
        indicators.append("Rapid probe pattern")

    if port in (21, 22, 3389) and duration >= 2 and packets > 150:
        score += 0.22
        indicators.append("Credential-service interaction")

    return min(score, 1.0), indicators


def compute_risk(
    ml_prediction: str,
    ml_confidence: float,
    anomaly_score: float,
    behavior_score: float,
    history_score: float = 0.0,
) -> tuple[int, str, str]:

    attack_weight = ATTACK_WEIGHTS.get(ml_prediction, 0.35)

    classification_signal = attack_weight * ml_confidence

    risk = (
        classification_signal * 60
        + anomaly_score * 20
        + behavior_score * 15
        + history_score * 5
    )

    risk_score = int(round(max(0.0, min(risk, 100.0))))

    if ml_prediction == "Normal" and risk_score < 35:
        return risk_score, "LOW", "ALLOW"

    if risk_score >= 85:
        return risk_score, "CRITICAL", "BLOCK"

    if risk_score >= 65:
        return risk_score, "HIGH", "ALERT"

    if risk_score >= 35:
        return risk_score, "MEDIUM", "MONITOR"

    return risk_score, "LOW", "ALLOW"