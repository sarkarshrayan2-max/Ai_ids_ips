import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.database.db import get_connection, init_db
from src.detection.incident_engine import correlate_incident, close_incident

SOURCE_IP = "198.51.100.40"


def clear_incidents():
    conn = get_connection()
    conn.execute("DELETE FROM incidents")
    conn.commit()
    conn.close()


def test_closed_incident_does_not_receive_new_events():
    init_db()
    clear_incidents()

    first_incident = correlate_incident(
        source_ip=SOURCE_IP,
        prediction="Port Scan",
        risk_score=75,
        action="ALERT",
    )

    assert first_incident is not None

    close_incident(first_incident)

    second_incident = correlate_incident(
        source_ip=SOURCE_IP,
        prediction="DDoS",
        risk_score=90,
        action="BLOCK",
    )

    assert second_incident is not None
    assert second_incident != first_incident

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
        WHERE source_ip=?
        ORDER BY id
        """,
        (SOURCE_IP,),
    ).fetchall()

    conn.close()

    assert len(rows) == 2

    old_incident = rows[0]
    new_incident = rows[1]

    assert old_incident["incident_id"] == first_incident
    assert old_incident["event_count"] == 1
    assert old_incident["max_risk"] == 75
    assert json.loads(old_incident["attack_types"]) == ["Port Scan"]
    assert old_incident["status"] == "CLOSED"

    assert new_incident["incident_id"] == second_incident
    assert new_incident["event_count"] == 1
    assert new_incident["max_risk"] == 90
    assert json.loads(new_incident["attack_types"]) == ["DDoS"]
    assert new_incident["status"] == "OPEN"
    assert new_incident["action"] == "BLOCK"