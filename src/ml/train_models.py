from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import (
    LabelEncoder,
    StandardScaler,
)

from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parents[2]

DATA = (
    ROOT
    / "data"
    / "sample"
    / "flow_dataset.csv"
)

MODEL_DIR = ROOT / "models"

FEATURES = [
    "destination_port",
    "duration",
    "packet_count",
    "byte_count",
    "packets_per_sec",
    "bytes_per_sec",
    "protocol_tcp",
]


def train():

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    df = pd.read_csv(DATA)

    X = df[FEATURES]
    y = df["label"]

    encoder = LabelEncoder()

    y_encoded = encoder.fit_transform(y)

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(X)

    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = train_test_split(
        X_scaled,
        y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded,
    )

    model = XGBClassifier(
        n_estimators=220,
        max_depth=6,
        learning_rate=0.06,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="mlogloss",
        random_state=42,
    )

    model.fit(
        X_train,
        y_train,
    )

    predictions = model.predict(
        X_test
    )

    report = classification_report(
        y_test,
        predictions,
        target_names=encoder.classes_,
        output_dict=True,
        zero_division=0,
    )

    metrics = {
        "dataset": "synthetic_flow_dataset",
        "evaluation_type": "synthetic_holdout",
        "sample_count": len(df),
        "accuracy": accuracy_score(
            y_test,
            predictions,
        ),
        "macro_precision": precision_score(
            y_test,
            predictions,
            average="macro",
            zero_division=0,
        ),
        "macro_recall": recall_score(
            y_test,
            predictions,
            average="macro",
            zero_division=0,
        ),
        "macro_f1": f1_score(
            y_test,
            predictions,
            average="macro",
            zero_division=0,
        ),
        "per_class": report,
    }

    normal_id = encoder.transform(
        ["Normal"]
    )[0]

    normal_train = X_train[
        y_train == normal_id
    ]

    normal_calibration, _ = train_test_split(
        normal_train,
        test_size=0.2,
        random_state=42,
    )

    isolation_forest = IsolationForest(
        n_estimators=180,
        contamination=0.03,
        random_state=42,
    )

    isolation_forest.fit(
        normal_train
    )

    calibration_scores = isolation_forest.score_samples(
        normal_calibration
    )

    low_score = float(
        np.percentile(
            calibration_scores,
            2.5,
        )
    )

    high_score = float(
        np.percentile(
            calibration_scores,
            97.5,
        )
    )

    if high_score <= low_score:
        high_score = low_score + 1e-6

    anomaly_calibration = {
        "low_score": low_score,
        "high_score": high_score,
        "normal_false_positive_percentile": 2.5,
    }

    calibration_path = (
        MODEL_DIR
        / "anomaly_calibration.json"
    )

    calibration_path.write_text(
        json.dumps(
            anomaly_calibration,
            indent=2,
        )
    )

    joblib.dump(
        model,
        MODEL_DIR / "xgboost_model.pkl",
    )

    joblib.dump(
        isolation_forest,
        MODEL_DIR / "isolation_forest.pkl",
    )

    joblib.dump(
        scaler,
        MODEL_DIR / "scaler.pkl",
    )

    joblib.dump(
        encoder,
        MODEL_DIR / "label_encoder.pkl",
    )

    (
        MODEL_DIR / "metrics.json"
    ).write_text(
        json.dumps(
            metrics,
            indent=2,
        )
    )

    print(
        classification_report(
            y_test,
            predictions,
            target_names=encoder.classes_,
            zero_division=0,
        )
    )

    print(
        f"Isolation Forest calibration:"
    )

    print(
        f"  low_score  = {low_score:.6f}"
    )

    print(
        f"  high_score = {high_score:.6f}"
    )

    print(
        f"Saved anomaly calibration to {calibration_path}"
    )

    print(
        f"Saved model artifacts to {MODEL_DIR}"
    )


if __name__ == "__main__":
    train()