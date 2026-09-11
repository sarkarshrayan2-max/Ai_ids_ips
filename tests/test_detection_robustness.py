import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.capture.traffic_generator import create_synthetic_flow
from src.database.db import get_connection
from src.detection.detection_engine import analyze_and_record_flow


ATTACKER_IP = "198.51.100.50"


def run_case(flow_type):
    conn = get_connection()

    conn.execute(
        """
        DELETE FROM flow_events
        WHERE source_ip=?
        """,
        (ATTACKER_IP,),
    )

    conn.commit()
    conn.close()

    flow = create_synthetic_flow(
        flow_type,
        source_ip=ATTACKER_IP,
    )

    result = analyze_and_record_flow(flow)

    print(f"\n{flow_type}")
    print(f"Prediction    : {result['prediction']}")
    print(f"Confidence    : {result['confidence']:.4f}")
    print(f"Anomaly       : {result['anomaly_score']:.4f}")
    print(f"Behavior      : {result['behavior_score']:.4f}")
    print(f"History       : {result['history_score']:.4f}")
    print(f"Risk          : {result['risk_score']}")
    print(f"Severity      : {result['severity']}")
    print(f"Action        : {result['action']}")
    print(f"Indicators    : {result['indicators']}")

    return result


def test_normal_detection():
    result = run_case("Normal")

    assert result["prediction"] == "Normal"
    assert result["risk_score"] < 35
    assert result["action"] == "ALLOW"


def test_port_scan_detection():
    result = run_case("Port Scan")

    assert result["prediction"] == "Port Scan"
    assert result["risk_score"] >= 35
    assert result["severity"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert result["action"] in {"MONITOR", "ALERT", "BLOCK"}


def test_brute_force_detection():
    result = run_case("Brute Force")

    assert result["prediction"] == "Brute Force"
    assert result["risk_score"] >= 35
    assert result["severity"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert result["action"] in {"MONITOR", "ALERT", "BLOCK"}


def test_ddos_detection():
    result = run_case("DDoS")

    assert result["prediction"] == "DDoS"
    assert result["anomaly_score"] >= 0.85
    assert result["behavior_score"] >= 0.50
    assert result["risk_score"] >= 85
    assert result["severity"] == "CRITICAL"
    assert result["action"] == "BLOCK"