from __future__ import annotations


ATTACK_WEIGHTS = {
    "Normal": 0.00,
    "Port Scan": 0.62,
    "Brute Force": 0.78,
    "DDoS": 0.95,
}


ML_WEIGHT = 50.0
ANOMALY_WEIGHT = 20.0
BEHAVIOR_WEIGHT = 20.0
HISTORY_WEIGHT = 10.0

INDEPENDENT_ANOMALY_WEIGHT = 75.0
INDEPENDENT_BEHAVIOR_WEIGHT = 100.0


def compute_behavior_score(flow: dict) -> tuple[float, list[str]]:
    score = 0.0
    indicators = []

    pps = float(flow.get("packets_per_sec", 0))
    bps = float(flow.get("bytes_per_sec", 0))
    duration = float(flow.get("duration", 0))
    packets = int(flow.get("packet_count", 0))
    port = int(flow.get("destination_port", 0))

    if pps >= 2000:
        score += 0.50
        indicators.append("Extreme packet-rate surge")
    elif pps >= 500:
        score += 0.30
        indicators.append("High packet-rate surge")
    elif pps >= 100:
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

    ml_confidence = max(0.0, min(float(ml_confidence), 1.0))
    anomaly_score = max(0.0, min(float(anomaly_score), 1.0))
    behavior_score = max(0.0, min(float(behavior_score), 1.0))
    history_score = max(0.0, min(float(history_score), 1.0))

    attack_weight = ATTACK_WEIGHTS.get(ml_prediction, 0.35)

    classification_signal = attack_weight * ml_confidence

    weighted_risk = (
        classification_signal * ML_WEIGHT
        + anomaly_score * ANOMALY_WEIGHT
        + behavior_score * BEHAVIOR_WEIGHT
        + history_score * HISTORY_WEIGHT
    )

    if ml_prediction == "Normal":
        if anomaly_score < 0.85:
            anomaly_component = (anomaly_score ** 2.0) * 30.0
        else:
            anomaly_component = anomaly_score * INDEPENDENT_ANOMALY_WEIGHT
    else:
        anomaly_component = anomaly_score * INDEPENDENT_ANOMALY_WEIGHT

    behavior_component = behavior_score * INDEPENDENT_BEHAVIOR_WEIGHT

    strong_anomaly = anomaly_score >= 0.85
    strong_behavior = behavior_score >= 0.60

    if ml_prediction == "Normal" and strong_anomaly and strong_behavior:
        independent_evidence = min(
            100.0,
            (anomaly_score * 55.0) + (behavior_score * 55.0),
        )
    else:
        independent_evidence = max(
            anomaly_component,
            behavior_component,
            (
                anomaly_score * 45.0
                + behavior_score * 45.0
                + history_score * 10.0
            ),
        )

    risk = max(weighted_risk, independent_evidence)

    if (
        ml_prediction == "Normal"
        and anomaly_score >= 0.85
        and behavior_score >= 0.50
    ):
        risk = max(risk, 85.0)

    if (
        ml_prediction == "DDoS"
        and ml_confidence >= 0.90
        and anomaly_score >= 0.85
    ):
        risk = max(risk, 85.0)

    risk_score = int(round(max(0.0, min(risk, 100.0))))

    if risk_score >= 85:
        return risk_score, "CRITICAL", "BLOCK"

    if risk_score >= 65:
        return risk_score, "HIGH", "ALERT"

    if risk_score >= 35:
        return risk_score, "MEDIUM", "MONITOR"

    return risk_score, "LOW", "ALLOW"
