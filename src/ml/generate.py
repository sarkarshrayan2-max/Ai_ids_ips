import numpy as np
import pandas as pd

def generate_synthetic_flows(n_samples=15000):
    np.random.seed(42)
    data = []
    
    classes = ["Normal", "DDoS", "Port Scan", "Brute Force"]
    weights = [0.65, 0.15, 0.10, 0.10]
    labels = np.random.choice(classes, size=n_samples, p=weights)
    
    for label in labels:
        if label == "Normal":
            duration = np.random.uniform(0.1, 15.0)
            packets = np.random.randint(5, 120)
            bytes_count = packets * np.random.randint(64, 1400)
            dst_port = np.random.choice([80, 443, 53, 22, 8080])
            protocol = np.random.choice(["TCP", "UDP"], p=[0.8, 0.2])
        elif label == "DDoS":
            duration = np.random.uniform(0.01, 1.5)
            packets = np.random.randint(1500, 10000)
            bytes_count = packets * np.random.randint(40, 120)
            dst_port = np.random.choice([80, 443])
            protocol = "TCP"
        elif label == "Port Scan":
            duration = np.random.uniform(0.001, 0.1)
            packets = np.random.randint(1, 4)
            bytes_count = packets * 40
            dst_port = np.random.randint(1, 65535)
            protocol = "TCP"
        elif label == "Brute Force":
            duration = np.random.uniform(2.0, 30.0)
            packets = np.random.randint(200, 800)
            bytes_count = packets * np.random.randint(100, 300)
            dst_port = np.random.choice([22, 3389, 21])
            protocol = "TCP"
            
        pps = packets / max(duration, 0.001)
        bps = bytes_count / max(duration, 0.001)
        
        data.append({
            "destination_port": dst_port,
            "duration": duration,
            "packet_count": packets,
            "byte_count": bytes_count,
            "packets_per_sec": pps,
            "bytes_per_sec": bps,
            "protocol_tcp": 1 if protocol == "TCP" else 0,
            "label": label
        })

    df = pd.DataFrame(data)
    df.to_csv("data/sample/flow_dataset.csv", index=False)
    print(f"Generated {n_samples} flow records at data/sample/flow_dataset.csv")

if __name__ == "__main__":
    generate_synthetic_flows()