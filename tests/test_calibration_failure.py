import importlib
import json

import pytest

import src.detection.detection_engine as detection_engine


def test_detection_fails_with_invalid_anomaly_calibration(
    monkeypatch,
):
    invalid_calibration = {
        "low_score": "invalid",
        "high_score": 0.0,
    }

    monkeypatch.setattr(
        detection_engine,
        "ANOMALY_CALIBRATION",
        invalid_calibration,
    )

    with pytest.raises(ValueError):
        detection_engine._calibrated_anomaly_score(-0.25)