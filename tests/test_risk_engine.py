from src.detection.risk_engine import compute_risk


def assert_result(result, minimum_score, severity, action):
    risk_score, actual_severity, actual_action = result
    assert risk_score >= minimum_score
    assert actual_severity == severity
    assert actual_action == action


def test_normal_low_evidence_allows():
    result = compute_risk("Normal", 0.99, 0.05, 0.05, 0.0)
    assert_result(result, 0, "LOW", "ALLOW")


def test_normal_strong_anomaly_cannot_be_ignored():
    result = compute_risk("Normal", 0.99, 0.90, 0.05, 0.0)
    assert_result(result, 60, "HIGH", "ALERT")


def test_normal_strong_behavior_cannot_be_ignored():
    result = compute_risk("Normal", 0.99, 0.05, 0.70, 0.0)
    assert_result(result, 65, "HIGH", "ALERT")


def test_normal_strong_anomaly_and_behavior_is_blocked():
    result = compute_risk("Normal", 0.99, 0.90, 0.70, 0.0)
    assert_result(result, 85, "CRITICAL", "BLOCK")


def test_attack_classification_still_contributes():
    result = compute_risk("Brute Force", 0.90, 0.10, 0.10, 0.0)
    assert_result(result, 35, "MEDIUM", "MONITOR")