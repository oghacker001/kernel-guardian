#!/usr/bin/env python3

import os
import re
import pwd
import json
from datetime import datetime, timezone, timedelta

# Always use Nishant's actual project directory,
# even when this program is executed with sudo.
PROJECT = "/home/nishant/kernel-guardian"

TRACE_FILE = "/sys/kernel/debug/tracing/trace_pipe"
LOG_FILE = os.path.join(PROJECT, "guardian_events.jsonl")

PATTERN = re.compile(
    r"comm=(?P<parent>\S+)\s+"
    r"pid=(?P<ppid>\d+)\s+"
    r"child_comm=(?P<child>\S+)\s+"
    r"child_pid=(?P<pid>\d+)"
)


def get_username(pid):
    try:
        uid = os.stat(f"/proc/{pid}").st_uid
        username = pwd.getpwuid(uid).pw_name
        return username, uid

    except (
        FileNotFoundError,
        ProcessLookupError,
        PermissionError,
        KeyError
    ):
        return "unknown", -1


def get_exe(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")

    except (
        FileNotFoundError,
        ProcessLookupError,
        PermissionError,
        OSError
    ):
        return "unknown"


def is_kernel_thread(name, exe):
    """
    Detect Linux kernel threads.

    Kernel threads generally do not have a normal
    userspace executable under /proc/<pid>/exe.
    """

    kernel_prefixes = (
        "kworker",
        "kthreadd",
        "migration",
        "idle",
        "cpuhp",
        "watchdog",
        "ksoftirqd",
        "rcu_",
        "mm_percpu_wq",
    )

    return (
        exe == "unknown"
        and name.startswith(kernel_prefixes)
    )


def classify(username, uid, exe, child_name):

    # Kernel threads should not be treated
    # as suspicious simply because they have
    # no executable.
    if is_kernel_thread(child_name, exe):
        return "KERNEL_THREAD", 0, []

    risk_score = 0
    reasons = []

    # Root execution
    if uid == 0:
        risk_score += 20
        reasons.append("root execution")

    # We don't know the UID.
    if uid == -1:
        reasons.append("user unavailable")

    # Unknown executable
    if exe == "unknown":
        risk_score += 10
        reasons.append("executable unavailable")

    # Sensitive executables
    sensitive = (
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/usr/bin/pkexec",
        "/usr/bin/passwd",
        "/usr/bin/chmod",
        "/usr/bin/chown",
    )

    if exe in sensitive:
        risk_score += 25
        reasons.append("sensitive executable")

    # Executable running from temporary locations
    suspicious_locations = (
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
    )

    if any(exe.startswith(path) for path in suspicious_locations):
        risk_score += 40
        reasons.append("executable from temporary location")

    # Severity
    if risk_score >= 70:
        classification = "CRITICAL"

    elif risk_score >= 40:
        classification = "HIGH"

    elif risk_score > 0:
        classification = "PRIVILEGED"

    else:
        classification = "NORMAL"

    return classification, risk_score, reasons


def get_timestamp():

    # IST
    ist = timezone(timedelta(hours=5, minutes=30))

    return datetime.now(ist).isoformat()


def main():

    os.makedirs(PROJECT, exist_ok=True)

    print("=" * 70)
    print("KERNEL GUARDIAN v1.5")
    print("Linux Kernel Process Security Monitor")
    print("=" * 70)

    print(f"[+] Project : {PROJECT}")
    print(f"[+] Log     : {LOG_FILE}")
    print("[+] Starting kernel process monitor...")
    print()

    with open(LOG_FILE, "a", buffering=1) as logfile:

        with open(TRACE_FILE, "r") as trace:

            for line in trace:

                match = PATTERN.search(line)

                if not match:
                    continue

                parent = match.group("parent")
                parent_pid = int(match.group("ppid"))

                child = match.group("child")
                child_pid = int(match.group("pid"))

                username, uid = get_username(child_pid)

                exe = get_exe(child_pid)

                classification, risk_score, reasons = classify(
                    username,
                    uid,
                    exe,
                    child
                )

                event = {
                    "timestamp": get_timestamp(),

                    "event": "PROCESS_CREATED",

                    "parent": {
                        "name": parent,
                        "pid": parent_pid
                    },

                    "child": {
                        "name": child,
                        "pid": child_pid
                    },

                    "security": {
                        "username": username,
                        "uid": uid,
                        "classification": classification,
                        "risk_score": risk_score,
                        "reasons": reasons
                    },

                    "executable": exe
                }

                # JSONL: one JSON object per line
                logfile.write(
                    json.dumps(event) + "\n"
                )

                print(
                    f"[{event['timestamp']}] "
                    f"[PROCESS CREATED] "
                    f"{parent}[{parent_pid}] -> "
                    f"{child}[{child_pid}] "
                    f"user={username} "
                    f"class={classification} "
                    f"risk={risk_score} "
                    f"exe={exe}"
                )


if __name__ == "__main__":
    main()
