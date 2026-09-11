from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]

OUT = (
    ROOT
    / "data"
    / "sample"
    / "flow_dataset.csv"
)


def generate_synthetic_flows(
    n_samples=30000,
):

    rng = np.random.default_rng(42)

    classes = [
        "Normal",
        "DDoS",
        "Port Scan",
        "Brute Force",
    ]

    weights = [
        0.65,
        0.15,
        0.10,
        0.10,
    ]

    labels = rng.choice(
        classes,
        size=n_samples,
        p=weights,
    )

    rows = []

    for label in labels:

        if label == "Normal":

            duration = rng.uniform(
                0.1,
                15.0,
            )

            packets = rng.integers(
                5,
                120,
            )

            bytes_count = (
                packets
                * rng.integers(
                    64,
                    1400,
                )
            )

            dst_port = rng.choice(
                [
                    80,
                    443,
                    53,
                    22,
                    8080,
                ]
            )

            protocol_tcp = int(
                rng.random() < 0.8
            )

        elif label == "DDoS":

            duration = rng.uniform(
                0.01,
                1.5,
            )

            packets = rng.integers(
                1500,
                10000,
            )

            bytes_count = (
                packets
                * rng.integers(
                    40,
                    120,
                )
            )

            dst_port = rng.choice(
                [
                    80,
                    443,
                ]
            )

            protocol_tcp = 1

        elif label == "Port Scan":

            duration = rng.uniform(
                0.001,
                0.1,
            )

            packets = rng.integers(
                1,
                5,
            )

            bytes_count = (
                packets
                * rng.integers(
                    40,
                    80,
                )
            )

            dst_port = rng.integers(
                1,
                65536,
            )

            protocol_tcp = 1

        else:

            duration = rng.uniform(
                2.0,
                30.0,
            )

            packets = rng.integers(
                200,
                800,
            )

            bytes_count = (
                packets
                * rng.integers(
                    100,
                    300,
                )
            )

            dst_port = rng.choice(
                [
                    21,
                    22,
                    3389,
                ]
            )

            protocol_tcp = 1

        packets_per_sec = (
            packets
            / max(
                duration,
                0.001,
            )
        )

        bytes_per_sec = (
            bytes_count
            / max(
                duration,
                0.001,
            )
        )

        rows.append(
            {
                "destination_port": int(
                    dst_port
                ),
                "duration": float(
                    duration
                ),
                "packet_count": int(
                    packets
                ),
                "byte_count": int(
                    bytes_count
                ),
                "packets_per_sec": float(
                    packets_per_sec
                ),
                "bytes_per_sec": float(
                    bytes_per_sec
                ),
                "protocol_tcp": protocol_tcp,
                "label": label,
            }
        )

    OUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    pd.DataFrame(rows).to_csv(
        OUT,
        index=False,
    )

    print(
        f"Generated {n_samples} flows at {OUT}"
    )


if __name__ == "__main__":
    generate_synthetic_flows()