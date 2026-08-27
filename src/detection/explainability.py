def explain_flow(flow_row: dict) -> list[str]:
    reasons = []

    pred = flow_row.get("ml_prediction")
    conf = flow_row.get("ml_confidence", 0)
    if pred != "Normal":
        reasons.append(f"🎯 **Signature Matched:** High confidence ({conf*100:.1f}%) classification as **{pred}**.")

    pps = flow_row.get("packets_per_sec", 0)
    if pps > 2000:
        reasons.append(f"⚡ **Volumetric Surge:** Packet rate at **{pps:,.0f} pkts/sec** (threshold > 2,000).")

    port = flow_row.get("destination_port", 0)
    duration = flow_row.get("duration", 0)
    pkts = flow_row.get("packet_count", 0)
    if pkts <= 5 and duration < 0.1 and port > 1024:
        reasons.append(f" **Probe Pattern:** Rapid single-packet connection to port **{port}** in {duration:.4f}s.")

    if port in [22, 3389, 21] and duration > 2.0 and pkts > 150:
        service = {22: "SSH", 3389: "RDP", 21: "FTP"}.get(port, str(port))
        reasons.append(f" **Credential Attempt:** Extended interaction on auth port **{port} ({service})** with {pkts} packets.")

    anomaly_score = flow_row.get("anomaly_score", 0)
    if anomaly_score >= 0.5:
        reasons.append(f" **Statistical Outlier:** Isolation Forest anomaly score **{anomaly_score:.2f}** deviates from baseline.")

    if not reasons:
        reasons.append(" Traffic profile conforms to standard baseline behavior.")

    return reasons