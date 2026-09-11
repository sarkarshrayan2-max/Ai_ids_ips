import random
import time

from src.detection.detection_engine import analyze_and_record_flow


NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.13",
    "192.168.1.14",
    "192.168.1.15",
    "192.168.1.16",
    "192.168.1.17",
    "192.168.1.18",
    "192.168.1.19",
    "192.168.1.20",
    "192.168.1.21",
    "192.168.1.22",
    "192.168.1.23",
    "192.168.1.24",
    "192.168.1.25",
    "192.168.1.26",
    "192.168.1.27",
    "192.168.1.28",
    "192.168.1.29",
]

ATTACKER_IPS = [
    "10.0.0.99",
    "185.220.101.5",
    "45.154.255.88",
    "198.51.100.23",
]

TARGET_SERVER = "192.168.1.100"


def create_synthetic_flow(flow_type="Normal", source_ip=None):
    if flow_type == "Normal":
        src_ip = source_ip or random.choice(NORMAL_IPS)

        duration = random.uniform(1.0, 15.0)

        packets_per_sec_target = random.lognormvariate(2.0, 0.8)
        packets_per_sec_target = min(
            packets_per_sec_target,
            250.0,
        )

        packets = max(
            5,
            int(packets_per_sec_target * duration),
        )

        packets = min(
            packets,
            119,
        )

        bytes_count = packets * random.randint(
            64,
            1400,
        )

        dst_port = random.choice([
            80,
            443,
            53,
            22,
            8080,
        ])

        source_port = random.randint(
            1024,
            65535,
        )

        protocol = random.choice([
            "TCP",
            "UDP",
        ])

    elif flow_type == "DDoS":
        src_ip = source_ip or random.choice(ATTACKER_IPS)

        duration = random.uniform(
            0.01,
            1.5,
        )

        packets = random.randint(
            1500,
            10000,
        )

        bytes_count = packets * random.randint(
            40,
            120,
        )

        dst_port = random.choice([
            80,
            443,
        ])

        source_port = random.randint(
            1024,
            65535,
        )

        protocol = "TCP"

    elif flow_type == "Port Scan":
        src_ip = source_ip or random.choice(ATTACKER_IPS)

        duration = random.uniform(
            0.001,
            0.1,
        )

        packets = random.randint(
            1,
            4,
        )

        bytes_count = packets * random.randint(
            40,
            80,
        )

        dst_port = random.randint(
            1,
            65535,
        )

        source_port = random.randint(
            1024,
            65535,
        )

        protocol = "TCP"

    elif flow_type == "Brute Force":
        src_ip = source_ip or random.choice(ATTACKER_IPS)

        duration = random.uniform(
            2,
            30,
        )

        packets = random.randint(
            200,
            800,
        )

        bytes_count = packets * random.randint(
            100,
            300,
        )

        dst_port = random.choice([
            21,
            22,
            3389,
        ])

        source_port = random.randint(
            1024,
            65535,
        )

        protocol = "TCP"

    else:
        raise ValueError(
            f"Unsupported flow type: {flow_type}"
        )

    packets_per_sec = packets / max(
        duration,
        0.001,
    )

    bytes_per_sec = bytes_count / max(
        duration,
        0.001,
    )

    protocol_tcp = 1 if protocol == "TCP" else 0

    return {
        "source_ip": src_ip,
        "destination_ip": TARGET_SERVER,
        "source_port": source_port,
        "destination_port": dst_port,
        "protocol": protocol,
        "protocol_tcp": protocol_tcp,
        "duration": duration,
        "packet_count": packets,
        "byte_count": bytes_count,
        "packets_per_sec": packets_per_sec,
        "bytes_per_sec": bytes_per_sec,
    }


def run_attack_burst(
    flow_type,
    count=5,
    source_ip=None,
    delay=0.2,
):
    results = []

    attacker_ip = source_ip or random.choice(
        ATTACKER_IPS
    )

    for _ in range(count):
        flow = create_synthetic_flow(
            flow_type,
            source_ip=attacker_ip,
        )

        result = analyze_and_record_flow(
            flow
        )

        results.append(result)

        if delay > 0:
            time.sleep(delay)

    return results


def run_traffic_stream(
    count=50,
    delay=0.5,
):
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

    results = []

    for _ in range(count):
        flow_type = random.choices(
            flow_types,
            weights=weights,
            k=1,
        )[0]

        flow = create_synthetic_flow(
            flow_type
        )

        result = analyze_and_record_flow(
            flow
        )

        results.append(result)

        if delay > 0:
            time.sleep(delay)

    return results