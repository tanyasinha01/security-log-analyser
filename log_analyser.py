import re
from collections import defaultdict
from datetime import datetime

# ── CONFIG ──────────────────────────────────────────
LOG_FILE = "auth.log"
BRUTE_FORCE_THRESHOLD = 3   # failed attempts to trigger alert
# ────────────────────────────────────────────────────

failed_attempts = defaultdict(list)
successful_logins = []
privilege_escalations = []
invalid_user_attempts = defaultdict(int)

def parse_log(filepath):
    with open(filepath, "r") as f:
        for line in f:
            # Detect failed password attempts
            if "Failed password" in line:
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                user_match = re.search(r'for (?:invalid user )?(\S+) from', line)
                if ip_match:
                    ip = ip_match.group(1)
                    user = user_match.group(1) if user_match else "unknown"
                    failed_attempts[ip].append(user)
                if "invalid user" in line:
                    if ip_match:
                        invalid_user_attempts[ip_match.group(1)] += 1

            # Detect successful logins
            elif "Accepted password" in line:
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                user_match = re.search(r'for (\S+) from', line)
                if ip_match and user_match:
                    successful_logins.append({
                        "user": user_match.group(1),
                        "ip": ip_match.group(1),
                        "line": line.strip()
                    })

            # Detect privilege escalation (sudo to root)
            elif "sudo" in line and "USER=root" in line:
                privilege_escalations.append(line.strip())

def generate_report():
    print("=" * 60)
    print("       SECURITY LOG ANALYSIS REPORT")
    print(f"       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # ── Brute Force Detection ──
    print("\n[!] BRUTE FORCE / REPEATED FAILED LOGIN ALERTS")
    print("-" * 60)
    found_brute = False
    for ip, users in failed_attempts.items():
        if len(users) >= BRUTE_FORCE_THRESHOLD:
            found_brute = True
            print(f"  ALERT  | IP: {ip}")
            print(f"          | Failed Attempts : {len(users)}")
            print(f"          | Targeted Users  : {', '.join(set(users))}")
            print(f"          | Severity        : HIGH")
            print()
    if not found_brute:
        print("  No brute force activity detected.\n")

    # ── Invalid User Attempts ──
    print("[!] INVALID USER LOGIN ATTEMPTS")
    print("-" * 60)
    if invalid_user_attempts:
        for ip, count in invalid_user_attempts.items():
            print(f"  WARN   | IP: {ip} tried {count} invalid usernames")
    else:
        print("  None detected.")
    print()

    # ── Successful Logins ──
    print("[*] SUCCESSFUL LOGINS (Review for anomalies)")
    print("-" * 60)
    for login in successful_logins:
        print(f"  INFO   | User: {login['user']} | IP: {login['ip']}")
    print()

    # ── Privilege Escalation ──
    print("[!] PRIVILEGE ESCALATION EVENTS")
    print("-" * 60)
    if privilege_escalations:
        for event in privilege_escalations:
            print(f"  ALERT  | {event}")
    else:
        print("  None detected.")
    print()

    # ── Summary ──
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    brute_ips = [ip for ip, u in failed_attempts.items() if len(u) >= BRUTE_FORCE_THRESHOLD]
    print(f"  Brute Force IPs Detected    : {len(brute_ips)}")
    print(f"  Successful Logins           : {len(successful_logins)}")
    print(f"  Privilege Escalation Events : {len(privilege_escalations)}")
    print(f"  Invalid User Attempts       : {sum(invalid_user_attempts.values())}")
    print("=" * 60)

if __name__ == "__main__":
    parse_log(LOG_FILE)
    generate_report()