import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_detection_module_fails_when_model_artifact_is_missing(
    monkeypatch,
):
    import src.detection.detection_engine as detection_engine

    original_load = detection_engine.joblib.load

    def failing_load(path):
        if Path(path).name == "xgboost_model.pkl":
            raise FileNotFoundError(
                "Simulated missing XGBoost model"
            )

        return original_load(path)

    monkeypatch.setattr(
        detection_engine.joblib,
        "load",
        failing_load,
    )

    with pytest.raises(
        FileNotFoundError,
        match="Simulated missing XGBoost model",
    ):
        importlib.reload(detection_engine)