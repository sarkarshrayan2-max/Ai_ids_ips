import sqlite3
from pathlib import Path

DB_PATH = str(Path(__file__).resolve().parents[2] / "ids_ips.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _add_column(cursor, table, column, definition):
    columns = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

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
            protocol_tcp INTEGER DEFAULT 0,
            ml_prediction TEXT,
            ml_confidence REAL,
            anomaly_score REAL,
            behavior_score REAL DEFAULT 0,
            history_score REAL DEFAULT 0,
            risk_score INTEGER,
            severity TEXT,
            action TEXT,
            incident_id TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE NOT NULL,
            source_ip TEXT NOT NULL,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_count INTEGER DEFAULT 1,
            max_risk INTEGER DEFAULT 0,
            attack_types TEXT DEFAULT '[]',
            status TEXT DEFAULT 'OPEN',
            action TEXT DEFAULT 'MONITOR'
        )
    """)

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

    _add_column(cursor, "flow_events", "protocol_tcp", "INTEGER DEFAULT 0")
    _add_column(cursor, "flow_events", "behavior_score", "REAL DEFAULT 0")
    _add_column(cursor, "flow_events", "history_score", "REAL DEFAULT 0")
    _add_column(cursor, "flow_events", "incident_id", "TEXT")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()