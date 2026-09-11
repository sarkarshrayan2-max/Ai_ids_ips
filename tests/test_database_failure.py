import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import src.database.db as db
from src.detection.detection_engine import analyze_and_record_flow


def test_detection_handles_database_failure(monkeypatch):
    def failing_connection():
        raise RuntimeError("Simulated database failure")

    monkeypatch.setattr(db, "get_connection", failing_connection)

    flow = {
        "source_ip": "198.51.100.70",
        "destination_ip": "10.0.0.1",
        "source_port": 4444,
        "destination_port": 80,
        "protocol": "TCP",
        "duration": 0.5,
        "packet_count": 100,
        "byte_count": 50000,
        "packets_per_sec": 200.0,
        "bytes_per_sec": 100000.0,
        "protocol_tcp": 1,
    }

    with pytest.raises(RuntimeError, match="Simulated database failure"):
        analyze_and_record_flow(flow)