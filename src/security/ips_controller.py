from __future__ import annotations

from src.database.db import get_connection


class IPSController:

    def __init__(self, enforcement_mode: bool = False):
        self.enforcement_mode = enforcement_mode

    def block_ip(
        self,
        source_ip: str,
        reason: str,
        risk_score: int,
    ) -> str:

        conn = get_connection()

        conn.execute(
            """
            INSERT INTO blocked_sources (
                source_ip,
                reason,
                risk_score,
                status
            )
            VALUES (?, ?, ?, 'BLOCKED')
            ON CONFLICT(source_ip)
            DO UPDATE SET
                reason=excluded.reason,
                risk_score=MAX(
                    blocked_sources.risk_score,
                    excluded.risk_score
                ),
                status='BLOCKED'
            """,
            (
                source_ip,
                reason,
                risk_score,
            ),
        )

        conn.commit()
        conn.close()

        if self.enforcement_mode:
            return "ENFORCED_BLOCK"

        return "SIMULATED_BLOCK"

    def unblock_ip(self, source_ip: str):

        conn = get_connection()

        conn.execute(
            """
            UPDATE blocked_sources
            SET status='RELEASED'
            WHERE source_ip=?
            """,
            (source_ip,),
        )

        conn.commit()
        conn.close()

    def is_blocked(self, source_ip: str) -> bool:

        conn = get_connection()

        row = conn.execute(
            """
            SELECT 1
            FROM blocked_sources
            WHERE source_ip=?
              AND status='BLOCKED'
            LIMIT 1
            """,
            (source_ip,),
        ).fetchone()

        conn.close()

        return row is not None