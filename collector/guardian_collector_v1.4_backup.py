#!/usr/bin/env python3

import os
import re
import pwd
import json
import time
from datetime import datetime

PROJECT = os.path.expanduser("~/kernel-guardian")

TRACE_FILE = "/sys/kernel/debug/tracing/trace_pipe"
LOG_FILE = os.path.join(PROJECT, "guardian_events.log")
JSON_FILE = os.path.join(PROJECT, "guardian_events.jsonl")

PATTERN = re.compile(
    r"comm=(?P<parent>\S+) "
    r"pid=(?P<ppid>\d+) "
    r"child_comm=(?P<child>\S+) "
    r"child_pid=(?P<pid>\d+)"
)

# Processes that are commonly legitimate even when running as root.
KNOWN_SYSTEM_PROCESSES = {
    "systemd",
    "sudo",
    "bash",
    "sh",
    "sleep",
    "kworker",
    "cron",
    "sshd",
    "dbus-daemon",
}

# Executables that deserve additional attention.
SENSITIVE_EXECUTABLES = {
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chmod",
    "/usr/bin/chown",
}


def get_username(pid):
    try:
        stat = os.stat(f"/proc/{pid}")
        uid = stat.st_uid
        username = pwd.getpwuid(uid).pw_name
        return username, uid
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return "unknown", -1


def get_exe(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except (
        FileNotFoundError,
        ProcessLookupError,
        PermissionError,
        OSError,
    ):
        return "unknown"


def calculate_risk(parent, child, username, uid, exe):
    score = 0
    reasons = []

    # Root execution gets attention, but is NOT automatically malicious.
    if uid == 0:
        score += 20
        reasons.append("root execution")

    # Sensitive administrative binaries.
    if exe in SENSITIVE_EXECUTABLES:
        score += 25
        reasons.append("sensitive executable")

    # Unknown executable.
    if exe == "unknown":
        score += 10
        reasons.append("executable unavailable")

    # Unknown user.
    if username == "unknown":
        score += 10
        reasons.append("user unavailable")

    # Very unusual parent/child relationship.
    if parent == "kworker" and child not in KNOWN_SYSTEM_PROCESSES:
        score += 20
        reasons.append("unusual kernel-worker child")

    if score >= 50:
        classification = "SUSPICIOUS"
    elif score >= 20:
        classification = "PRIVILEGED"
    else:
        classification = "NORMAL"

    return score, classification, reasons


def create_event(parent, ppid, child, pid):
    username, uid = get_username(pid)
    exe = get_exe(pid)

    score, classification, reasons = calculate_risk(
        parent,
        child,
        username,
        uid,
        exe,
    )

    timestamp = datetime.now().astimezone().isoformat()

    return {
        "timestamp": timestamp,
        "event": "PROCESS_CREATED",

        "parent": {
            "name": parent,
            "pid": ppid,
        },

        "child": {
            "name": child,
            "pid": pid,
        },

        "security": {
            "username": username,
            "uid": uid,
            "classification": classification,
            "risk_score": score,
            "reasons": reasons,
        },

        "executable": exe,
    }


def write_event(event):
    timestamp = event["timestamp"]

    parent = event["parent"]
    child = event["child"]
    security = event["security"]

    line = (
        f"[{timestamp}] "
        f"[PROCESS CREATED] "
        f"parent={parent['name']}[{parent['pid']}] "
        f"child={child['name']}[{child['pid']}] "
        f"user={security['username']} "
        f"uid={security['uid']} "
        f"class={security['classification']} "
        f"risk={security['risk_score']} "
        f"exe={event['executable']}"
    )

    with open(LOG_FILE, "a", buffering=1) as logfile:
        logfile.write(line + "\n")

    with open(JSON_FILE, "a", buffering=1) as jsonfile:
        json.dump(event, jsonfile)
        jsonfile.write("\n")

    if security["classification"] == "SUSPICIOUS":
        print("\n" + "!" * 70)
        print("[!!! SECURITY ALERT !!!]")
        print(line)

        if security["reasons"]:
            print("Reasons:")
            for reason in security["reasons"]:
                print(f"  - {reason}")

        print("!" * 70)

    else:
        print(line)


def main():
    os.makedirs(PROJECT, exist_ok=True)

    print("=" * 70)
    print("KERNEL GUARDIAN v1.5")
    print("Linux Kernel Process Security Monitor")
    print("=" * 70)
    print(f"[+] Project : {PROJECT}")
    print(f"[+] Log     : {LOG_FILE}")
    print(f"[+] JSON    : {JSON_FILE}")
    print(f"[+] Trace   : {TRACE_FILE}")
    print("[+] Starting kernel process monitor...")
    print()

    if not os.path.exists(TRACE_FILE):
        print("[ERROR] trace_pipe not available.")
        print("[INFO] Make sure debugfs/tracing is mounted.")
        return

    try:
        with open(TRACE_FILE, "r", buffering=1) as trace:
            for line in trace:

                match = PATTERN.search(line)

                if not match:
                    continue

                event = create_event(
                    match.group("parent"),
                    int(match.group("ppid")),
                    match.group("child"),
                    int(match.group("pid")),
                )

                write_event(event)

    except KeyboardInterrupt:
        print("\n[+] Kernel Guardian stopped.")

    except PermissionError:
        print("[ERROR] Permission denied reading trace_pipe.")
        print("[INFO] Run the collector with sudo.")

    except Exception as exc:
        print(f"[ERROR] {exc}")


if __name__ == "__main__":
    main()
