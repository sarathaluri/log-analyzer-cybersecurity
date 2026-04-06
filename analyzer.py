import sys
from collections import defaultdict

def analyze_logs(file_path):
    failed_attempts = defaultdict(int)
    alerts = []

    try:
        with open(file_path, "r") as file:
            for line in file:
                parts = line.strip().split()

                if len(parts) < 5:
                    continue

                timestamp = parts[0] + " " + parts[1]
                ip = parts[2]
                status = parts[3]
                message = " ".join(parts[4:])

                if "Failed login" in message:
                    failed_attempts[ip] += 1

        # Generate alerts
        for ip, count in failed_attempts.items():
            if count >= 3:
                alerts.append(f"[HIGH] {ip} - Brute force suspected ({count} attempts)")
            elif count == 2:
                alerts.append(f"[MEDIUM] {ip} - Suspicious activity")
            elif count >= 5:
                alerts.append(f"[CRITICAL] {ip} - Severe brute force ({count})")
            elif count >= 3:
                alerts.append(f"[HIGH] {ip}")
            elif count == 2:
                alerts.append(f"[MEDIUM] {ip}")

        return alerts

    except FileNotFoundError:
        print("Error: Log file not found.")
        sys.exit(1)


def save_alerts(alerts):
    with open("alerts.txt", "w") as file:
        for alert in alerts:
            file.write(alert + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py logs.txt")
        sys.exit(1)

    log_file = sys.argv[1]
    alerts = analyze_logs(log_file)
    print("\n--- SUMMARY ---")
    print(f"Total suspicious IPs: {len(failed_attempts)}")
    print(f"Total alerts generated: {len(alerts)}")
    print("\n--- SECURITY ALERTS ---")
    for alert in alerts:
        print(alert)

    save_alerts(alerts)
