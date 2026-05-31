import random
from datetime import datetime, timedelta

# ── CONFIG ───────────────────────────────────────
TOTAL_LINES = 10000
OUTPUT_FILE = "auth.log"
# ─────────────────────────────────────────────────

# Attacker IPs — these will repeatedly fail
attacker_ips = [
    "45.33.32.156", "192.168.1.105", "10.0.0.15",
    "185.220.101.34", "103.99.0.122", "222.186.42.11"
]

# Normal user IPs — occasional successful logins
normal_ips = [
    "192.168.1.200", "192.168.1.201", "10.10.0.5", "203.0.113.42"
]

# Valid users on the server
valid_users = ["admin", "john", "tanya", "deploy", "ubuntu"]

# Users attackers try (mostly invalid)
attack_users = ["root", "test", "guest", "oracle", "postgres",
                "admin", "user", "pi", "ubuntu", "ftpuser"]

# Start time
start_time = datetime(2026, 1, 10, 0, 0, 0)

lines = []

for i in range(TOTAL_LINES):
    # Move time forward randomly (1 to 30 seconds)
    start_time += timedelta(seconds=random.randint(1, 30))
    timestamp = start_time.strftime("%b %d %H:%M:%S")
    pid = random.randint(1000, 9999)

    roll = random.random()

    if roll < 0.55:
        # 55% — failed login from attacker IP
        ip = random.choice(attacker_ips)
        user = random.choice(attack_users)
        if random.random() < 0.4:
            line = f"{timestamp} server sshd[{pid}]: Failed password for invalid user {user} from {ip} port 22 ssh2"
        else:
            line = f"{timestamp} server sshd[{pid}]: Failed password for {user} from {ip} port 22 ssh2"

    elif roll < 0.70:
        # 15% — successful login from normal IP
        ip = random.choice(normal_ips)
        user = random.choice(valid_users)
        line = f"{timestamp} server sshd[{pid}]: Accepted password for {user} from {ip} port 22 ssh2"

    elif roll < 0.78:
        # 8% — privilege escalation
        user = random.choice(valid_users)
        cmd = random.choice(["/bin/bash", "/usr/bin/vim", "/bin/cat /etc/shadow", "/usr/sbin/useradd"])
        line = f"{timestamp} server sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND={cmd}"

    elif roll < 0.86:
        # 8% — disconnection messages (noise)
        ip = random.choice(attacker_ips + normal_ips)
        line = f"{timestamp} server sshd[{pid}]: Disconnected from {ip} port 22"

    elif roll < 0.93:
        # 7% — connection closed (noise)
        ip = random.choice(attacker_ips)
        line = f"{timestamp} server sshd[{pid}]: Connection closed by {ip} port 22"

    else:
        # 7% — session opened
        user = random.choice(valid_users)
        line = f"{timestamp} server sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}"

    lines.append(line)

with open(OUTPUT_FILE, "w") as f:
    f.write("\n".join(lines))

print(f"Generated {TOTAL_LINES} log lines into '{OUTPUT_FILE}'")
print("Now run: python log_analyser.py")