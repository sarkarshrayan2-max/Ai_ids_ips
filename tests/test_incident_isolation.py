import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.database.db import get_connection, init_db
from src.detection.incident_engine import correlate_incident


SOURCE_A = "198.51.100.10"
SOURCE_B = "198.51.100.20"


def clear_incidents():
    conn = get_connection()
    conn.execute("DELETE FROM incidents")
    conn.commit()
    conn.close()


def test_different_sources_create_separate_incidents():
    init_db()
    clear_incidents()

    incident_a = correlate_incident(
        source_ip=SOURCE_A,
        prediction="Port Scan",
        risk_score=75,
        action="ALERT",
    )

    incident_b = correlate_incident(
        source_ip=SOURCE_B,
        prediction="Brute Force",
        risk_score=70,
        action="ALERT",
    )

    assert incident_a is not None
    assert incident_b is not None
    assert incident_a != incident_b

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            incident_id,
            source_ip,
            event_count,
            max_risk,
            attack_types,
            status,
            action
        FROM incidents
        WHERE source_ip IN (?, ?)
        ORDER BY source_ip
        """,
        (SOURCE_A, SOURCE_B),
    ).fetchall()

    conn.close()

    assert len(rows) == 2

    first = rows[0]
    second = rows[1]

    assert first["source_ip"] == SOURCE_A
    assert first["event_count"] == 1
    assert first["max_risk"] == 75
    assert json.loads(first["attack_types"]) == ["Port Scan"]
    assert first["status"] == "OPEN"
    assert first["action"] == "ALERT"

    assert second["source_ip"] == SOURCE_B
    assert second["event_count"] == 1
    assert second["max_risk"] == 70
    assert json.loads(second["attack_types"]) == ["Brute Force"]
    assert second["status"] == "OPEN"
    assert second["action"] == "ALERT"