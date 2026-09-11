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
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = Path(
    r"C:\Users\sarkar\Downloads\MachineLearningCVE"
)

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

EVALUATION_FILES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
]


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


def load_file(file_name):
    path = DATA_DIR / file_name

    if not path.exists():
        raise FileNotFoundError(
            f"Missing dataset file: {path}"
        )

    frames = []

    print(
        f"Processing: {file_name}"
    )

    for chunk in pd.read_csv(
        path,
        chunksize=100000,
        low_memory=False,
    ):
        processed = build_features(
            chunk
        )

        if not processed.empty:
            frames.append(processed)

    if not frames:
        raise RuntimeError(
            f"No supported rows found in {file_name}"
        )

    return pd.concat(
        frames,
        ignore_index=True,
    )


def chronological_split(df):
    split_index = int(
        len(df) * 0.8
    )

    train = df.iloc[
        :split_index
    ].copy()

    test = df.iloc[
        split_index:
    ].copy()

    return train, test


def main():
    print(
        "=============================="
    )
    print(
        "CIC SCENARIO-AWARE EVALUATION"
    )
    print(
        "=============================="
    )

    train_frames = []
    test_frames = []

    for file_name in EVALUATION_FILES:
        df = load_file(
            file_name
        )

        train_part, test_part = chronological_split(
            df
        )

        train_frames.append(
            train_part
        )

        test_frames.append(
            test_part
        )

        print(
            f"Total rows: {len(df)}"
        )

        print(
            f"Chronological train: {len(train_part)}"
        )

        print(
            f"Chronological test:  {len(test_part)}"
        )

    train_df = pd.concat(
        train_frames,
        ignore_index=True,
    )

    test_df = pd.concat(
        test_frames,
        ignore_index=True,
    )

    print(
        "\n=============================="
    )
    print(
        "DATASET SUMMARY"
    )
    print(
        "=============================="
    )

    print(
        f"Training flows: {len(train_df)}"
    )

    print(
        f"Testing flows:  {len(test_df)}"
    )

    print(
        "\nTraining class distribution:"
    )

    print(
        train_df["label"].value_counts()
    )

    print(
        "\nTesting class distribution:"
    )

    print(
        test_df["label"].value_counts()
    )

    missing_train = set(
        test_df["label"].unique()
    ) - set(
        train_df["label"].unique()
    )

    if missing_train:
        raise RuntimeError(
            "Test contains classes absent from training: "
            + str(sorted(missing_train))
        )

    X_train = train_df[FEATURES]
    y_train = train_df["label"]

    X_test = test_df[FEATURES]
    y_test = test_df["label"]

    encoder = LabelEncoder()

    y_train_encoded = encoder.fit_transform(
        y_train
    )

    y_test_encoded = encoder.transform(
        y_test
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
        "\nTraining scenario-aware model..."
    )

    model.fit(
        X_train_scaled,
        y_train_encoded,
    )

    predictions = model.predict(
        X_test_scaled
    )

    predicted_labels = (
        encoder.inverse_transform(
            predictions
        )
    )

    labels = [
        "Normal",
        "DDoS",
        "Port Scan",
        "Brute Force",
    ]

    print(
        "\n=============================="
    )
    print(
        "SCENARIO-AWARE RESULTS"
    )
    print(
        "=============================="
    )

    print(
        f"Accuracy: {accuracy_score(y_test, predicted_labels):.4f}"
    )

    print(
        f"Macro Precision: {precision_score(y_test, predicted_labels, average='macro', zero_division=0):.4f}"
    )

    print(
        f"Macro Recall: {recall_score(y_test, predicted_labels, average='macro', zero_division=0):.4f}"
    )

    print(
        f"Macro F1: {f1_score(y_test, predicted_labels, average='macro', zero_division=0):.4f}"
    )

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_test,
            predicted_labels,
            labels=labels,
            zero_division=0,
        )
    )

    print(
        "Confusion Matrix:"
    )

    matrix = confusion_matrix(
        y_test,
        predicted_labels,
        labels=labels,
    )

    print(matrix)


if __name__ == "__main__":
    main()