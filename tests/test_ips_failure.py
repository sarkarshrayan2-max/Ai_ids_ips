import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import src.database.db as db
import src.security.ips_controller as ips_module
from src.security.ips_controller import IPSController


SOURCE_IP = "198.51.100.80"


def test_ips_failure_is_surfaced(monkeypatch):
    db.init_db()

    controller = IPSController(enforcement_mode=False)

    def failing_connection():
        raise RuntimeError("Simulated IPS database failure")

    monkeypatch.setattr(
        ips_module,
        "get_connection",
        failing_connection,
    )

    with pytest.raises(
        RuntimeError,
        match="Simulated IPS database failure",
    ):
        controller.block_ip(
            source_ip=SOURCE_IP,
            reason="Critical DDoS threat",
            risk_score=90,
        )