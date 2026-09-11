from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from src.database.db import get_connection


INCIDENT_WINDOW_MINUTES = 10


def _new_incident_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:6].upper()
    return f"INC-{timestamp}-{suffix}"


def _append_attack_type(
    attack_types: list[str],
    prediction: str,
) -> list[str]:

    if prediction != "Normal" and prediction not in attack_types:
        attack_types.append(prediction)

    return attack_types


def correlate_incident(
    source_ip: str,
    prediction: str,
    risk_score: int,
    action: str,
) -> str | None:

    if risk_score < 35:
        return None

    conn = get_connection()

    existing = conn.execute(
        """
        SELECT
            incident_id,
            event_count,
            max_risk,
            attack_types
        FROM incidents
        WHERE source_ip=?
          AND status='OPEN'
          AND datetime(last_seen) >= datetime(
              'now',
              ?
          )
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            source_ip,
            f"-{INCIDENT_WINDOW_MINUTES} minutes",
        ),
    ).fetchone()

    if existing:

        incident_id = existing["incident_id"]

        try:
            attack_types = json.loads(
                existing["attack_types"] or "[]"
            )

            if not isinstance(
                attack_types,
                list,
            ):
                attack_types = []

        except json.JSONDecodeError:
            attack_types = []

        attack_types = _append_attack_type(
            attack_types,
            prediction,
        )

        event_count = (
            int(existing["event_count"]) + 1
        )

        max_risk = max(
            int(existing["max_risk"]),
            risk_score,
        )

        conn.execute(
            """
            UPDATE incidents
            SET
                last_seen=CURRENT_TIMESTAMP,
                event_count=?,
                max_risk=?,
                attack_types=?,
                action=?
            WHERE incident_id=?
            """,
            (
                event_count,
                max_risk,
                json.dumps(
                    attack_types
                ),
                action,
                incident_id,
            ),
        )

    else:

        incident_id = _new_incident_id()

        attack_types = []

        attack_types = _append_attack_type(
            attack_types,
            prediction,
        )

        conn.execute(
            """
            INSERT INTO incidents (
                incident_id,
                source_ip,
                event_count,
                max_risk,
                attack_types,
                status,
                action
            )
            VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                'OPEN',
                ?
            )
            """,
            (
                incident_id,
                source_ip,
                1,
                risk_score,
                json.dumps(
                    attack_types
                ),
                action,
            ),
        )

    conn.commit()
    conn.close()

    return incident_id


def close_incident(
    incident_id: str,
):
    conn = get_connection()

    conn.execute(
        """
        UPDATE incidents
        SET status='CLOSED'
        WHERE incident_id=?
        """,
        (incident_id,),
    )

    conn.commit()
    conn.close()