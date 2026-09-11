import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import src.database.db as db
import src.security.ips_controller as ips_module
from src.security.ips_controller import IPSController


SOURCE_IP = "198.51.100.81"


def test_ips_recovers_after_failure():
    db.init_db()

    controller = IPSController(enforcement_mode=False)

    original_get_connection = ips_module.get_connection

    def failing_connection():
        raise RuntimeError("Simulated IPS database failure")

    ips_module.get_connection = failing_connection

    try:
        try:
            controller.block_ip(
                source_ip=SOURCE_IP,
                reason="Critical DDoS threat",
                risk_score=90,
            )
        except RuntimeError as exc:
            assert str(exc) == "Simulated IPS database failure"
    finally:
        ips_module.get_connection = original_get_connection

    result = controller.block_ip(
        source_ip=SOURCE_IP,
        reason="Critical DDoS threat",
        risk_score=90,
    )

    assert result == "SIMULATED_BLOCK"

    assert controller.is_blocked(SOURCE_IP)

    conn = db.get_connection()

    row = conn.execute(
        """
        SELECT
            source_ip,
            reason,
            risk_score,
            status
        FROM blocked_sources
        WHERE source_ip=?
        """,
        (SOURCE_IP,),
    ).fetchone()

    conn.close()

    assert row is not None
    assert row["source_ip"] == SOURCE_IP
    assert row["risk_score"] == 90
    assert row["status"] == "BLOCKED"