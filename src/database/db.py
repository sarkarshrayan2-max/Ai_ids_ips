import sqlite3

DB_PATH = "ids_ips.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Flow Logs & Detections
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flow_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            duration REAL,
            packet_count INTEGER,
            byte_count INTEGER,
            packets_per_sec REAL,
            bytes_per_sec REAL,
            ml_prediction TEXT,
            ml_confidence REAL,
            anomaly_score REAL,
            risk_score INTEGER,
            severity TEXT,
            action TEXT
        )
    """)

    # 2. Blocked Sources Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT UNIQUE,
            reason TEXT,
            risk_score INTEGER,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'BLOCKED'
        )
    """)
    conn.commit()
    conn.close()
    print("[+] Database initialized successfully.")

if __name__ == "__main__":
    init_db()