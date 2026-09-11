from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


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


MODEL_FILES = {
    "model": MODEL_DIR / "xgboost_model.pkl",
    "scaler": MODEL_DIR / "scaler.pkl",
    "encoder": MODEL_DIR / "label_encoder.pkl",
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

    df = df.dropna(
        subset=[
            "Destination Port",
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets",
            "Flow Packets/s",
            "Flow Bytes/s",
        ]
    )

    packet_count = (
        pd.to_numeric(
            df["Total Fwd Packets"],
            errors="coerce",
        )
        + pd.to_numeric(
            df["Total Backward Packets"],
            errors="coerce",
        )
    )

    byte_count = (
        pd.to_numeric(
            df["Total Length of Fwd Packets"],
            errors="coerce",
        )
        + pd.to_numeric(
            df["Total Length of Bwd Packets"],
            errors="coerce",
        )
    )

    duration = (
        pd.to_numeric(
            df["Flow Duration"],
            errors="coerce",
        )
        / 1_000_000.0
    )

    packets_per_sec = pd.to_numeric(
        df["Flow Packets/s"],
        errors="coerce",
    )

    bytes_per_sec = pd.to_numeric(
        df["Flow Bytes/s"],
        errors="coerce",
    )

    destination_port = pd.to_numeric(
        df["Destination Port"],
        errors="coerce",
    )

    tcp_signal = (
        pd.to_numeric(
            df["SYN Flag Count"],
            errors="coerce",
        ).fillna(0)
        + pd.to_numeric(
            df["ACK Flag Count"],
            errors="coerce",
        ).fillna(0)
        + pd.to_numeric(
            df["RST Flag Count"],
            errors="coerce",
        ).fillna(0)
        + pd.to_numeric(
            df["FIN Flag Count"],
            errors="coerce",
        ).fillna(0)
    )

    protocol_tcp = (
        tcp_signal > 0
    ).astype(int)

    result = pd.DataFrame(
        {
            "destination_port": destination_port,
            "duration": duration,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec": bytes_per_sec,
            "protocol_tcp": protocol_tcp,
            "label": (
                df["Label"]
                .astype(str)
                .str.strip()
                .map(LABEL_MAP)
            ),
        }
    )

    result = result.dropna(
        subset=FEATURES + ["label"]
    )

    result = result.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    result = result.dropna(
        subset=FEATURES
    )

    return result


def evaluate_file(
    path,
    model,
    scaler,
    encoder,
):
    y_true = []
    y_pred = []

    total_rows = 0

    for chunk in pd.read_csv(
        path,
        chunksize=100000,
        low_memory=False,
    ):
        chunk = build_features(chunk)

        if chunk.empty:
            continue

        X = chunk[FEATURES]

        X_scaled = scaler.transform(X)

        predictions = model.predict(
            X_scaled
        )

        predicted_labels = encoder.inverse_transform(
            predictions
        )

        y_true.extend(
            chunk["label"].tolist()
        )

        y_pred.extend(
            predicted_labels.tolist()
        )

        total_rows += len(chunk)

    if not y_true:
        return None

    return {
        "rows": total_rows,
        "y_true": y_true,
        "y_pred": y_pred,
    }


def main():

    model = joblib.load(
        MODEL_FILES["model"]
    )

    scaler = joblib.load(
        MODEL_FILES["scaler"]
    )

    encoder = joblib.load(
        MODEL_FILES["encoder"]
    )

    all_true = []
    all_pred = []

    csv_files = sorted(
        DATA_DIR.glob("*.csv")
    )

    print(
        f"Found {len(csv_files)} CSV files."
    )

    for path in csv_files:

        print(
            f"\nProcessing: {path.name}"
        )

        result = evaluate_file(
            path,
            model,
            scaler,
            encoder,
        )

        if result is None:
            print(
                "No supported labels found."
            )
            continue

        all_true.extend(
            result["y_true"]
        )

        all_pred.extend(
            result["y_pred"]
        )

        print(
            f"Evaluated rows: {result['rows']}"
        )

    print(
        "\n=============================="
    )

    print(
        "CIC-IDS2017 EVALUATION"
    )

    print(
        "=============================="
    )

    print(
        f"Total evaluated flows: {len(all_true)}"
    )

    print(
        f"Accuracy: {accuracy_score(all_true, all_pred):.4f}"
    )

    print(
        f"Macro Precision: {precision_score(all_true, all_pred, average='macro', zero_division=0):.4f}"
    )

    print(
        f"Macro Recall: {recall_score(all_true, all_pred, average='macro', zero_division=0):.4f}"
    )

    print(
        f"Macro F1: {f1_score(all_true, all_pred, average='macro', zero_division=0):.4f}"
    )

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            all_true,
            all_pred,
            labels=[
                "Normal",
                "DDoS",
                "Port Scan",
                "Brute Force",
            ],
            zero_division=0,
        )
    )

    print(
        "Confusion Matrix:"
    )

    matrix = confusion_matrix(
        all_true,
        all_pred,
        labels=[
            "Normal",
            "DDoS",
            "Port Scan",
            "Brute Force",
        ],
    )

    print(matrix)


if __name__ == "__main__":
    main()