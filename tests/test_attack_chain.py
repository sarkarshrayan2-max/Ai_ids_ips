from src.capture.traffic_generator import create_synthetic_flow
from src.detection.detection_engine import analyze_and_record_flow
from src.database.db import get_connection, init_db


ATTACKER_IP = "203.0.113.50"


def run_attack_chain():

    init_db()

    print("\n" + "=" * 60)
    print("AI SENTINEL ATTACK CHAIN TEST")
    print("=" * 60)

    attack_sequence = [
        "Port Scan",
        "Brute Force",
        "DDoS",
    ]

    results = []

    for attack_type in attack_sequence:

        print(f"\n[+] Simulating {attack_type}")

        flow = create_synthetic_flow(
            attack_type,
            source_ip=ATTACKER_IP,
        )

        result = analyze_and_record_flow(flow)

        results.append(result)

        print(
            f"    Prediction : {result['prediction']}"
        )

        print(
            f"    Risk       : {result['risk_score']}/100"
        )

        print(
            f"    Severity   : {result['severity']}"
        )

        print(
            f"    Action     : {result['action']}"
        )

        print(
            f"    Incident   : {result['incident_id']}"
        )

    conn = get_connection()

    incident = conn.execute(
        """
        SELECT
            incident_id,
            source_ip,
            event_count,
            max_risk,
            attack_types,
            status,
            action
        FROM incidents
        WHERE source_ip=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (ATTACKER_IP,),
    ).fetchone()

    conn.close()

    print("\n" + "=" * 60)
    print("ATTACK CHAIN RESULT")
    print("=" * 60)

    if incident:

        print(
            f"Incident ID : {incident['incident_id']}"
        )

        print(
            f"Source      : {incident['source_ip']}"
        )

        print(
            f"Events      : {incident['event_count']}"
        )

        print(
            f"Max Risk    : {incident['max_risk']}"
        )

        print(
            f"Attack Chain: {incident['attack_types']}"
        )

        print(
            f"Status      : {incident['status']}"
        )

        print(
            f"Action      : {incident['action']}"
        )

        if incident["event_count"] >= 3:
            print("\nPASS: All attack stages were correlated.")

        else:
            print("\nFAIL: Attack stages were not fully correlated.")

    else:

        print("\nFAIL: No incident was created.")


if __name__ == "__main__":
    run_attack_chain()