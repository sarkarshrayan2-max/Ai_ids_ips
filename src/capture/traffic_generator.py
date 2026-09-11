import random
import time

from src.detection.detection_engine import (
    analyze_and_record_flow,
)


NORMAL_IPS = [
    f"192.168.1.{i}"
    for i in range(10, 30)
]

ATTACKER_IPS = [
    "10.0.0.99",
    "185.220.101.5",
    "45.154.255.88",
    "198.51.100.23",
]

TARGET_SERVER = "192.168.1.100"


def create_synthetic_flow(
    flow_type="Normal",
    source_ip=None,
):

    if flow_type == "Normal":

        src_ip = source_ip or random.choice(
            NORMAL_IPS
        )

        duration = random.uniform(
            0.1,
            15.0,
        )

        packets = random.randint(
            5,
            120,
        )

        bytes_count = (
            packets
            * random.randint(
                64,
                1400,
            )
        )

        dst_port = random.choice(
            [
                80,
                443,
                53,
                22,
                8080,
            ]
        )

        protocol = random.choice(
            [
                "TCP",
                "UDP",
            ]
        )

    elif flow_type == "DDoS":

        src_ip = source_ip or random.choice(
            ATTACKER_IPS
        )

        duration = random.uniform(
            0.01,
            1.5,
        )

        packets = random.randint(
            1500,
            10000,
        )

        bytes_count = (
            packets
            * random.randint(
                40,
                120,
            )
        )

        dst_port = random.choice(
            [
                80,
                443,
            ]
        )

        protocol = "TCP"

    elif flow_type == "Port Scan":

        src_ip = source_ip or random.choice(
            ATTACKER_IPS
        )

        duration = random.uniform(
            0.001,
            0.1,
        )

        packets = random.randint(
            1,
            4,
        )

        bytes_count = (
            packets
            * random.randint(
                40,
                80,
            )
        )

        dst_port = random.randint(
            1,
            65535,
        )

        protocol = "TCP"

    elif flow_type == "Brute Force":

        src_ip = source_ip or random.choice(
            ATTACKER_IPS
        )

        duration = random.uniform(
            2.0,
            30.0,
        )

        packets = random.randint(
            200,
            800,
        )

        bytes_count = (
            packets
            * random.randint(
                100,
                300,
            )
        )

        dst_port = random.choice(
            [
                22,
                3389,
                21,
            ]
        )

        protocol = "TCP"

    else:
        raise ValueError(
            f"Unsupported flow type: {flow_type}"
        )

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

    return {
        "source_ip": src_ip,
        "destination_ip": TARGET_SERVER,
        "source_port": random.randint(
            1024,
            65535,
        ),
        "destination_port": dst_port,
        "protocol": protocol,
        "duration": duration,
        "packet_count": packets,
        "byte_count": bytes_count,
        "packets_per_sec": packets_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "protocol_tcp": int(
            protocol == "TCP"
        ),
    }


def run_attack_burst(
    flow_type,
    count=10,
):

    source_ip = random.choice(
        ATTACKER_IPS
    )

    results = []

    for _ in range(count):

        flow = create_synthetic_flow(
            flow_type,
            source_ip=source_ip,
        )

        result = analyze_and_record_flow(
            flow
        )

        results.append(result)

    return results


def run_traffic_stream(
    delay=1.0,
):

    print(
        "[*] Starting AI Sentinel traffic stream."
    )

    flow_types = [
        "Normal",
        "DDoS",
        "Port Scan",
        "Brute Force",
    ]

    weights = [
        0.70,
        0.10,
        0.10,
        0.10,
    ]

    while True:

        flow_type = random.choices(
            flow_types,
            weights=weights,
        )[0]

        flow = create_synthetic_flow(
            flow_type
        )

        result = analyze_and_record_flow(
            flow
        )

        print(
            f"[{result['severity']}] "
            f"{result['source_ip']} -> "
            f"{result['prediction']} | "
            f"Risk={result['risk_score']} | "
            f"Action={result['action']} | "
            f"Incident={result['incident_id']}"
        )

        time.sleep(delay)


if __name__ == "__main__":
    run_traffic_stream(
        delay=1.5
    )