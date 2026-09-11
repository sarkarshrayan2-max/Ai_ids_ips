import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.detection.risk_engine import compute_risk


def test_normal_prediction_cannot_override_strong_attack_evidence():
    risk_score, severity, action = compute_risk(
        ml_prediction="Normal",
        ml_confidence=0.99,
        anomaly_score=0.90,
        behavior_score=0.70,
        history_score=0.0,
    )

    print("\nMISCLASSIFICATION RESILIENCE TEST")
    print(f"ML Prediction : Normal")
    print(f"ML Confidence : 0.9900")
    print(f"Anomaly       : 0.9000")
    print(f"Behavior      : 0.7000")
    print(f"Risk          : {risk_score}")
    print(f"Severity      : {severity}")
    print(f"Action        : {action}")

    assert risk_score >= 85
    assert severity == "CRITICAL"
    assert action == "BLOCK"