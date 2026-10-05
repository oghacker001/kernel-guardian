#!/usr/bin/env python3

import json
import os
import time
from datetime import datetime, timezone, timedelta

PROJECT = "/home/nishant/kernel-guardian"

EVENT_LOG = os.path.join(PROJECT, "guardian_events.jsonl")
ALERT_LOG = os.path.join(PROJECT, "guardian_alerts.jsonl")

# Minimum score required to generate an alert
ALERT_THRESHOLD = 40

SENSITIVE_EXECUTABLES = {
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chmod",
    "/usr/bin/chown",
    "/usr/bin/mount",
    "/usr/bin/umount",
}

KNOWN_SYSTEM_PARENTS = {
    "systemd",
    "kthreadd",
    "pool-spawner",
    "preload",
}


def classify_alert(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"


def calculate_detection(event):

    security = event.get("security", {})

    username = security.get("username", "unknown")
    executable = event.get("executable", "unknown")

    parent = event.get("parent", {})
    parent_name = parent.get("name", "unknown")

    score = 0
    reasons = []

    # -------------------------------------------------
    # ROOT EXECUTION
    # -------------------------------------------------

    if username == "root":
        score += 20
        reasons.append("root execution")

    # -------------------------------------------------
    # SENSITIVE EXECUTABLE
    # -------------------------------------------------

    if executable in SENSITIVE_EXECUTABLES:
        score += 25
        reasons.append("sensitive executable")

    # -------------------------------------------------
    # UNKNOWN EXECUTABLE
    # -------------------------------------------------

    if executable == "unknown":
        score += 10
        reasons.append("executable unavailable")

    # -------------------------------------------------
    # UNKNOWN USER
    # -------------------------------------------------

    if username == "unknown":
        score += 10
        reasons.append("user unavailable")

    # -------------------------------------------------
    # SUSPICIOUS PARENT
    # -------------------------------------------------

    if parent_name not in KNOWN_SYSTEM_PARENTS:

        if parent_name in {
            "bash",
            "sh",
            "python",
            "python3",
            "perl",
            "ruby",
            "node",
        }:
            score += 10
            reasons.append("script interpreter parent")

    # -------------------------------------------------
    # SECURITY CLASSIFICATION FROM COLLECTOR
    # -------------------------------------------------

    collector_classification = security.get(
        "classification",
        "NORMAL"
    )

    if collector_classification == "PRIVILEGED" and username != "root":
        score += 10
        reasons.append("privileged classification")

    return score, reasons


def create_alert(event, score, reasons):

    executable = event.get("executable", "unknown")

    parent = event.get("parent", {})
    child = event.get("child", {})

    username = event.get(
        "security",
        {}
    ).get(
        "username",
        "unknown"
    )

    uid = event.get(
        "security",
        {}
    ).get(
        "uid",
        -1
    )

    severity = classify_alert(score)

    # IST timestamp
    ist = timezone(timedelta(hours=5, minutes=30))

    alert = {
        "timestamp": datetime.now(ist).isoformat(),
        "alert": "SECURITY_ALERT",
        "severity": severity,
        "risk_score": score,

        "event": {
            "type": event.get(
                "event",
                "UNKNOWN"
            ),

            "parent": parent,

            "child": child,

            "executable": executable
        },

        "security": {
            "username": username,
            "uid": uid,
            "reasons": reasons
        }
    }

    with open(
        ALERT_LOG,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            json.dumps(
                alert,
                separators=(",", ":")
            )
            + "\n"
        )

    print()
    print("=" * 70)
    print("🚨 KERNEL GUARDIAN SECURITY ALERT")
    print("=" * 70)
    print(f"Severity    : {severity}")
    print(f"Risk Score  : {score}")
    print(f"User        : {username}")
    print(f"Executable  : {executable}")
    print(
        f"Parent      : "
        f"{parent.get('name', 'unknown')}"
        f"[{parent.get('pid', -1)}]"
    )
    print(
        f"Child       : "
        f"{child.get('name', 'unknown')}"
        f"[{child.get('pid', -1)}]"
    )

    print("Reasons     :")

    for reason in reasons:
        print(f"  - {reason}")

    print("=" * 70)
    print()


def process_event(event):

    if not isinstance(event, dict):
        return

    if event.get("event") != "PROCESS_CREATED":
        return

    score, reasons = calculate_detection(event)

    if score < ALERT_THRESHOLD:
        return

    create_alert(
        event,
        score,
        reasons
    )


def follow_event_log():

    print("[+] Waiting for NEW security events...")
    print("[+] Reading:", EVENT_LOG)
    print("[+] Alert threshold:", ALERT_THRESHOLD)

    # Wait for collector log
    while not os.path.exists(EVENT_LOG):

        print(
            "[!] Waiting for event log..."
        )

        time.sleep(1)

    # Open event log
    with open(
        EVENT_LOG,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:

        # IMPORTANT:
        # Start at the END.
        # We only want NEW events.
        f.seek(0, os.SEEK_END)

        while True:

            line = f.readline()

            if not line:

                time.sleep(0.2)
                continue

            line = line.strip()

            if not line:
                continue

            try:

                event = json.loads(line)

                process_event(event)

            except json.JSONDecodeError:

                print(
                    "[!] Ignoring malformed JSON event"
                )

            except Exception as e:

                print(
                    "[!] Detector error:",
                    e
                )


def main():

    print("=" * 70)
    print("KERNEL GUARDIAN v3.0")
    print("Security Detection Engine")
    print("=" * 70)

    print("[+] Project    :", PROJECT)
    print("[+] Event log  :", EVENT_LOG)
    print("[+] Alert log  :", ALERT_LOG)
    print("[+] Threshold  :", ALERT_THRESHOLD)

    print("[+] Detection engine running...")

    follow_event_log()


if __name__ == "__main__":
    main()
