import pytest

from src.detection.detection_engine import analyze_and_record_flow


def test_detection_rejects_missing_required_feature():
    flow = {
        "source_ip": "10.0.0.50",
        "destination_ip": "192.168.1.10",
        "source_port": 45000,
        "destination_port": 80,
        "protocol": "TCP",
        "duration": 1.0,
        "packet_count": 100,
        "byte_count": 10000,
        "packets_per_sec": 100.0,
        "bytes_per_sec": 10000.0,
    }

    with pytest.raises((KeyError, ValueError)):
        analyze_and_record_flow(flow)