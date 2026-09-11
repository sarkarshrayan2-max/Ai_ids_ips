import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.capture.traffic_generator import create_synthetic_flow
from src.detection.detection_engine import analyze_and_record_flow


ATTACKER_IP = "198.51.100.60"


def test_high_risk_traffic_cannot_become_low_risk():
    flow = create_synthetic_flow(
        "DDoS",
        source_ip=ATTACKER_IP,
    )

    result = analyze_and_record_flow(flow)

    print("\nADVERSARIAL DETECTION TEST")
    print(f"Prediction    : {result['prediction']}")
    print(f"Confidence    : {result['confidence']:.4f}")
    print(f"Anomaly       : {result['anomaly_score']:.4f}")
    print(f"Behavior      : {result['behavior_score']:.4f}")
    print(f"History       : {result['history_score']:.4f}")
    print(f"Risk          : {result['risk_score']}")
    print(f"Severity      : {result['severity']}")
    print(f"Action        : {result['action']}")
    print(f"Indicators    : {result['indicators']}")

    assert result["anomaly_score"] >= 0.85

    assert result["risk_score"] >= 85
    assert result["severity"] == "CRITICAL"
    assert result["action"] == "BLOCK"