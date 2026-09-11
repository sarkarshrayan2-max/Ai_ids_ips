from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parents[2]

DATA_PATH = ROOT / "data" / "sample" / "flow_dataset.csv"
MODELS_DIR = ROOT / "models"

MODELS_DIR.mkdir(parents=True, exist_ok=True)


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
    df = pd.read_csv(DATA_PATH)

    required_columns = FEATURES + ["label"]

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    X = df[FEATURES].copy()
    y = df["label"].astype(str)

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.20,
        random_state=42,
        stratify=y_encoded,
    )

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    xgb_model = XGBClassifier(
        n_estimators=220,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="multi:softprob",
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )

    xgb_model.fit(
        X_train_scaled,
        y_train,
    )

    normal_label = label_encoder.transform(
        ["Normal"]
    )[0]

    normal_train = X_train_scaled[
        y_train == normal_label
    ]

    if len(normal_train) == 0:
        raise ValueError(
            "No Normal samples available for Isolation Forest training."
        )

    isolation_forest = IsolationForest(
        n_estimators=200,
        contamination=0.03,
        random_state=42,
        n_jobs=-1,
    )

    isolation_forest.fit(
        normal_train
    )

    calibration_scores = isolation_forest.score_samples(
        normal_train
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
        raise ValueError(
            "Invalid anomaly calibration range."
        )

    test_predictions = xgb_model.predict(
        X_test_scaled
    )

    test_accuracy = float(
        np.mean(
            test_predictions == y_test
        )
    )

    metrics = {
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "features": FEATURES,
        "classes": label_encoder.classes_.tolist(),
        "normal_label": int(normal_label),
        "test_accuracy": test_accuracy,
        "xgboost_parameters": {
            "n_estimators": 220,
            "max_depth": 6,
            "learning_rate": 0.08,
            "subsample": 0.9,
            "colsample_bytree": 0.9,
            "random_state": 42,
        },
        "isolation_forest": {
            "n_estimators": 200,
            "contamination": 0.03,
            "random_state": 42,
        },
    }

    calibration = {
        "low_score": low_score,
        "high_score": high_score,
        "normal_false_positive_percentile": 2.5,
        "calibration_samples": int(len(calibration_scores)),
        "calibration_method": "normal_train_percentiles",
    }

    joblib.dump(
        xgb_model,
        MODELS_DIR / "xgboost_model.pkl",
    )

    joblib.dump(
        scaler,
        MODELS_DIR / "scaler.pkl",
    )

    joblib.dump(
        label_encoder,
        MODELS_DIR / "label_encoder.pkl",
    )

    joblib.dump(
        isolation_forest,
        MODELS_DIR / "isolation_forest.pkl",
    )

    joblib.dump(
        metrics,
        MODELS_DIR / "training_metrics.pkl",
    )

    with (
        MODELS_DIR / "anomaly_calibration.json"
    ).open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            calibration,
            file,
            indent=2,
        )

    print("=" * 60)
    print("MODEL TRAINING COMPLETE")
    print("=" * 60)

    print(f"Dataset: {DATA_PATH}")
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    print(
        f"Classes: {label_encoder.classes_.tolist()}"
    )
    print(
        f"Test accuracy: {test_accuracy:.4f}"
    )

    print()
    print("Isolation Forest")
    print(
        f"Normal samples: {len(normal_train)}"
    )
    print(
        f"Calibration samples: {len(calibration_scores)}"
    )
    print(
        f"Score min: {calibration_scores.min():.6f}"
    )
    print(
        f"Score median: {np.median(calibration_scores):.6f}"
    )
    print(
        f"Score max: {calibration_scores.max():.6f}"
    )
    print(
        f"Low score: {low_score:.6f}"
    )
    print(
        f"High score: {high_score:.6f}"
    )

    print()
    print("Saved:")
    print("xgboost_model.pkl")
    print("scaler.pkl")
    print("label_encoder.pkl")
    print("isolation_forest.pkl")
    print("training_metrics.pkl")
    print("anomaly_calibration.json")


if __name__ == "__main__":
    train()