import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import src.database.db as db
from src.capture.traffic_generator import create_synthetic_flow
from src.detection.detection_engine import analyze_and_record_flow


SOURCE_IP = "198.51.100.71"


def test_detection_recovers_after_database_failure():
    db.init_db()

    flow = create_synthetic_flow(
        "Normal",
        source_ip=SOURCE_IP,
    )

    first_result = analyze_and_record_flow(flow)

    assert first_result["prediction"] == "Normal"

    original_get_connection = db.get_connection

    def failing_connection():
        raise RuntimeError("Simulated database failure")

    db.get_connection = failing_connection

    try:
        try:
            analyze_and_record_flow(flow)
        except RuntimeError as exc:
            assert str(exc) == "Simulated database failure"
    finally:
        db.get_connection = original_get_connection

    recovered_flow = create_synthetic_flow(
        "Normal",
        source_ip=SOURCE_IP,
    )

    recovered_result = analyze_and_record_flow(
        recovered_flow
    )

    assert recovered_result["prediction"] == "Normal"
    assert "risk_score" in recovered_result
    assert "severity" in recovered_result
    assert "action" in recovered_result

    conn = db.get_connection()

    row = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM flow_events
        WHERE source_ip=?
        """,
        (SOURCE_IP,),
    ).fetchone()

    conn.close()

    assert row["count"] >= 2