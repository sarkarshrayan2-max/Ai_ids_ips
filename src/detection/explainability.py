def explain_flow(flow_row: dict) -> list[str]:

    reasons = []

    prediction = flow_row.get("ml_prediction", "Normal")

    confidence = float(
        flow_row.get("ml_confidence", 0)
    )

    anomaly = float(
        flow_row.get("anomaly_score", 0)
    )

    behavior = float(
        flow_row.get("behavior_score", 0)
    )

    history = float(
        flow_row.get("history_score", 0)
    )

    packets_per_sec = float(
        flow_row.get("packets_per_sec", 0)
    )

    bytes_per_sec = float(
        flow_row.get("bytes_per_sec", 0)
    )

    destination_port = int(
        flow_row.get("destination_port", 0)
    )

    duration = float(
        flow_row.get("duration", 0)
    )

    packet_count = int(
        flow_row.get("packet_count", 0)
    )

    if prediction != "Normal":
        reasons.append(
            f"XGBoost classified the flow as {prediction} "
            f"with {confidence * 100:.1f}% confidence."
        )

    if packets_per_sec >= 5000:
        reasons.append(
            f"Extreme traffic volume detected: "
            f"{packets_per_sec:,.0f} packets/sec."
        )
    elif packets_per_sec >= 2000:
        reasons.append(
            f"High traffic volume detected: "
            f"{packets_per_sec:,.0f} packets/sec."
        )

    if bytes_per_sec >= 5_000_000:
        reasons.append(
            f"High bandwidth utilization detected: "
            f"{bytes_per_sec / 1_000_000:.2f} MB/s."
        )

    if (
        packet_count <= 5
        and duration < 0.1
        and destination_port > 1024
    ):
        reasons.append(
            f"Rapid reconnaissance behavior detected "
            f"against destination port {destination_port}."
        )

    if (
        destination_port in (21, 22, 3389)
        and duration >= 2
        and packet_count > 150
    ):
        reasons.append(
            f"Sustained authentication-service traffic "
            f"detected on port {destination_port}."
        )

    if anomaly >= 0.5:
        reasons.append(
            f"Isolation Forest identified anomalous behavior "
            f"with score {anomaly:.2f}."
        )

    if behavior >= 0.4:
        reasons.append(
            f"Behavior engine produced an elevated risk score "
            f"of {behavior:.2f}."
        )

    if history >= 0.4:
        reasons.append(
            f"Source history increased the threat score "
            f"to {history:.2f}."
        )

    if not reasons:
        reasons.append(
            "Traffic profile is consistent with the learned "
            "normal baseline."
        )

    return reasons