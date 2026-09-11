from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = Path(
    r"C:\Users\sarkar\Downloads\MachineLearningCVE"
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

LABEL_MAP = {
    "BENIGN": "Normal",
    "DDoS": "DDoS",
    "PortScan": "Port Scan",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "Web Attack � Brute Force": "Brute Force",
    "Web Attack – Brute Force": "Brute Force",
}


def clean_columns(df):
    df.columns = (
        df.columns
        .astype(str)
        .str.strip()
    )
    return df


def build_features(df):
    df = clean_columns(df)

    df = df.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    required_columns = [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Flow Packets/s",
        "Flow Bytes/s",
        "SYN Flag Count",
        "ACK Flag Count",
        "RST Flag Count",
        "FIN Flag Count",
        "Label",
    ]

    df = df.dropna(
        subset=required_columns
    )

    destination_port = pd.to_numeric(
        df["Destination Port"],
        errors="coerce",
    )

    duration = (
        pd.to_numeric(
            df["Flow Duration"],
            errors="coerce",
        )
        / 1_000_000.0
    )

    packet_count = (
        pd.to_numeric(
            df["Total Fwd Packets"],
            errors="coerce",
        )
        +
        pd.to_numeric(
            df["Total Backward Packets"],
            errors="coerce",
        )
    )

    byte_count = (
        pd.to_numeric(
            df["Total Length of Fwd Packets"],
            errors="coerce",
        )
        +
        pd.to_numeric(
            df["Total Length of Bwd Packets"],
            errors="coerce",
        )
    )

    packets_per_sec = pd.to_numeric(
        df["Flow Packets/s"],
        errors="coerce",
    )

    bytes_per_sec = pd.to_numeric(
        df["Flow Bytes/s"],
        errors="coerce",
    )

    tcp_signal = (
        pd.to_numeric(
            df["SYN Flag Count"],
            errors="coerce",
        ).fillna(0)
        +
        pd.to_numeric(
            df["ACK Flag Count"],
            errors="coerce",
        ).fillna(0)
        +
        pd.to_numeric(
            df["RST Flag Count"],
            errors="coerce",
        ).fillna(0)
        +
        pd.to_numeric(
            df["FIN Flag Count"],
            errors="coerce",
        ).fillna(0)
    )

    protocol_tcp = (
        tcp_signal > 0
    ).astype(int)

    labels = (
        df["Label"]
        .astype(str)
        .str.strip()
        .map(LABEL_MAP)
    )

    result = pd.DataFrame(
        {
            "destination_port": destination_port,
            "duration": duration,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec": bytes_per_sec,
            "protocol_tcp": protocol_tcp,
            "label": labels,
        }
    )

    result = result.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    result = result.dropna(
        subset=FEATURES + ["label"]
    )

    return result


def load_dataset():
    frames = []

    csv_files = sorted(
        DATA_DIR.glob("*.csv")
    )

    print(
        f"Found {len(csv_files)} CSV files."
    )

    for path in csv_files:
        print(
            f"Processing: {path.name}"
        )

        file_frames = []

        for chunk in pd.read_csv(
            path,
            chunksize=100000,
            low_memory=False,
        ):
            processed = build_features(
                chunk
            )

            if not processed.empty:
                file_frames.append(
                    processed
                )

        if file_frames:
            file_df = pd.concat(
                file_frames,
                ignore_index=True,
            )

            frames.append(file_df)

            print(
                f"Supported rows: {len(file_df)}"
            )

    if not frames:
        raise RuntimeError(
            "No supported CIC-IDS2017 rows found."
        )

    dataset = pd.concat(
        frames,
        ignore_index=True,
    )

    return dataset


def train():
    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    df = load_dataset()

    print(
        "\n=============================="
    )
    print(
        "CIC DATASET SUMMARY"
    )
    print(
        "=============================="
    )

    print(
        f"Total flows: {len(df)}"
    )

    print(
        "\nClass distribution:"
    )

    print(
        df["label"].value_counts()
    )

    X = df[FEATURES]
    y = df["label"]

    encoder = LabelEncoder()

    y_encoded = encoder.fit_transform(
        y
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded,
    )

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    X_test_scaled = scaler.transform(
        X_test
    )

    model = XGBClassifier(
        n_estimators=300,
        max_depth=7,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )

    print(
        "\nTraining CIC XGBoost model..."
    )

    model.fit(
        X_train_scaled,
        y_train,
    )

    predictions = model.predict(
        X_test_scaled
    )

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    macro_precision = precision_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0,
    )

    macro_recall = recall_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0,
    )

    macro_f1 = f1_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0,
    )

    report = classification_report(
        y_test,
        predictions,
        target_names=encoder.classes_,
        output_dict=True,
        zero_division=0,
    )

    metrics = {
        "dataset": "CIC-IDS2017",
        "evaluation_type": "CIC_holdout",
        "sample_count": len(df),
        "accuracy": accuracy,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
        "classes": encoder.classes_.tolist(),
        "per_class": report,
    }

    joblib.dump(
        model,
        MODEL_DIR / "cic_xgboost_model.pkl",
    )

    joblib.dump(
        scaler,
        MODEL_DIR / "cic_scaler.pkl",
    )

    joblib.dump(
        encoder,
        MODEL_DIR / "cic_label_encoder.pkl",
    )

    (
        MODEL_DIR / "cic_metrics.json"
    ).write_text(
        json.dumps(
            metrics,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        "\n=============================="
    )
    print(
        "CIC MODEL EVALUATION"
    )
    print(
        "=============================="
    )

    print(
        f"Accuracy: {accuracy:.4f}"
    )

    print(
        f"Macro Precision: {macro_precision:.4f}"
    )

    print(
        f"Macro Recall: {macro_recall:.4f}"
    )

    print(
        f"Macro F1: {macro_f1:.4f}"
    )

    print(
        "\nClassification Report:"
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
        "Confusion Matrix:"
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=range(
            len(encoder.classes_)
        ),
    )

    print(matrix)

    print(
        "\nSaved CIC model artifacts:"
    )

    print(
        MODEL_DIR / "cic_xgboost_model.pkl"
    )

    print(
        MODEL_DIR / "cic_scaler.pkl"
    )

    print(
        MODEL_DIR / "cic_label_encoder.pkl"
    )

    print(
        MODEL_DIR / "cic_metrics.json"
    )


if __name__ == "__main__":
    train()