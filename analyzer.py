import sys
from collections import defaultdict
import json


def analyze_logs(file_path):
    failed_attempts = defaultdict(int)
    alerts = []

    try:
        with open(file_path, "r") as file:
            for line in file:
                parts = line.strip().split()

                if len(parts) < 5:
                    continue

                ip = parts[2]
                message = " ".join(parts[4:])

                if "Failed login" in message:
                    failed_attempts[ip] += 1

        # Generate alerts (Correct order)
        for ip, count in failed_attempts.items():
	    
            if count >= 10:
                alerts.append(f"[CRITICAL] {ip} - Excessive activity detected")
            elif count >= 5:
                alerts.append(f"[CRITICAL] {ip} - Severe brute force ({count} attempts)")
            elif count >= 3:
                alerts.append(f"[HIGH] {ip} - Brute force suspected ({count} attempts)")
            elif count == 2:
                alerts.append(f"[MEDIUM] {ip} - Suspicious activity")

        return alerts, failed_attempts

    except FileNotFoundError:
        print("Error: Log file not found.")
        sys.exit(1)


def save_alerts(alerts):
    with open("alerts.txt", "w") as file:
        for alert in alerts:
            file.write(alert + "\n")


def save_json(alerts):
    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)


def get_severity(alert):
    if "[CRITICAL]" in alert:
        return 3
    elif "[HIGH]" in alert:
        return 2
    elif "[MEDIUM]" in alert:
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py logs.txt")
        sys.exit(1)

    log_file = sys.argv[1]

    alerts, failed_attempts = analyze_logs(log_file)

    # Sort alerts by severity
    alerts.sort(key=get_severity, reverse=True)

    # Tool banner
    print("=" * 45)
    print("      SOC LOG ANALYZER - PYTHON TOOL")
    print("=" * 45)

    print("\n--- SECURITY ALERTS ---")
    for alert in alerts:
        print(alert)

    # Save outputs
    save_alerts(alerts)
    save_json(alerts)

    # Summary
    high_count = sum(1 for a in alerts if "[HIGH]" in a)
    medium_count = sum(1 for a in alerts if "[MEDIUM]" in a)
    critical_count = sum(1 for a in alerts if "[CRITICAL]" in a)

    print("\n--- SUMMARY ---")
    print(f"Total suspicious IPs: {len(failed_attempts)}")
    print(f"Total alerts generated: {len(alerts)}")
    print(f"Critical alerts: {critical_count}")
    print(f"High alerts: {high_count}")
    print(f"Medium alerts: {medium_count}")