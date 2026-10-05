#!/bin/bash
set -e

USER_NAME="${SUDO_USER:-$USER}"
USER_HOME="$(eval echo "~$USER_NAME")"

PROJECT="$USER_HOME/kernel-guardian"
KERNEL_DIR="$PROJECT/kernel"
COLLECTOR_DIR="$PROJECT/collector"
LOG_FILE="$PROJECT/guardian_events.log"

echo "============================================================"
echo "        KERNEL GUARDIAN - COMPLETE SETUP"
echo "============================================================"
echo "[+] User    : $USER_NAME"
echo "[+] Project : $PROJECT"
echo "[+] Log     : $LOG_FILE"
echo

# ------------------------------------------------------------
# 1. Fix ownership
# ------------------------------------------------------------

echo "[+] Fixing project ownership..."

if [ -d "$PROJECT" ]; then
    chown -R "$USER_NAME:$USER_NAME" "$PROJECT" 2>/dev/null || true
fi

mkdir -p "$KERNEL_DIR"
mkdir -p "$COLLECTOR_DIR"

touch "$LOG_FILE"

chown "$USER_NAME:$USER_NAME" "$LOG_FILE"

# ------------------------------------------------------------
# 2. Create kernel module
# ------------------------------------------------------------

echo "[+] Creating kernel module..."

cat > "$KERNEL_DIR/guardian_main.c" <<'SRC'

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/err.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nishant");
MODULE_DESCRIPTION(
    "KERNEL GUARDIAN - Linux Kernel Security Monitoring Platform"
);
MODULE_VERSION("1.4");

static struct kretprobe guardian_rp;

/*
 * Entry handler
 */
static int guardian_entry_handler(
    struct kretprobe_instance *ri,
    struct pt_regs *regs)
{
    return 0;
}

/*
 * Return handler
 *
 * copy_process() returns a task_struct pointer on success.
 *
 * On x86-64 kernel pointers may have the high bit set, so
 * checking "ret > 0" is incorrect because a valid kernel
 * pointer can appear negative when stored in signed long.
 */
static int guardian_ret_handler(
    struct kretprobe_instance *ri,
    struct pt_regs *regs)
{
    unsigned long raw_ret;
    struct task_struct *child;

    raw_ret = (unsigned long)regs_return_value(regs);

    /*
     * copy_process() returns ERR_PTR() on failure.
     */
    if (IS_ERR_VALUE(raw_ret))
        return 0;

    if (raw_ret == 0)
        return 0;

    child = (struct task_struct *)raw_ret;

    /*
     * Basic sanity check before accessing task_struct.
     */
    if (!child)
        return 0;

    pr_info(
        "KERNEL GUARDIAN: PROCESS CREATED | "
        "parent=%s[%d] child=%s[%d]\n",
        current->comm,
        current->pid,
        child->comm,
        child->pid
    );

    return 0;
}

/*
 * Module initialization
 */
static int __init guardian_init(void)
{
    int ret;

    pr_info(
        "KERNEL GUARDIAN: module loaded successfully\n"
    );

    pr_info(
        "KERNEL GUARDIAN: registering copy_process kretprobe\n"
    );

    memset(&guardian_rp, 0, sizeof(guardian_rp));

    guardian_rp.kp.symbol_name = "copy_process";
    guardian_rp.entry_handler = guardian_entry_handler;
    guardian_rp.handler = guardian_ret_handler;
    guardian_rp.maxactive = 64;

    ret = register_kretprobe(&guardian_rp);

    if (ret < 0) {
        pr_err(
            "KERNEL GUARDIAN: failed to register kretprobe: %d\n",
            ret
        );

        return ret;
    }

    pr_info(
        "KERNEL GUARDIAN: copy_process kretprobe "
        "registered successfully\n"
    );

    return 0;
}

/*
 * Module cleanup
 */
static void __exit guardian_exit(void)
{
    unregister_kretprobe(&guardian_rp);

    pr_info(
        "KERNEL GUARDIAN: copy_process kretprobe unregistered\n"
    );

    pr_info(
        "KERNEL GUARDIAN: module unloaded successfully\n"
    );
}

module_init(guardian_init);
module_exit(guardian_exit);

SRC

# ------------------------------------------------------------
# 3. Makefile
# ------------------------------------------------------------

cat > "$KERNEL_DIR/Makefile" <<'MAKEFILE'

obj-m += guardian_main.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build \
	M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build \
	M=$(PWD) clean

MAKEFILE

# ------------------------------------------------------------
# 4. Create Python collector
# ------------------------------------------------------------

echo "[+] Creating collector..."

cat > "$COLLECTOR_DIR/guardian_collector.py" <<'PY'

#!/usr/bin/env python3

import os
import re
import pwd
import subprocess
from datetime import datetime

PROJECT = os.path.expanduser("~/kernel-guardian")
LOG_FILE = os.path.join(PROJECT, "guardian_events.log")

PATTERN = re.compile(
    r"KERNEL GUARDIAN: PROCESS CREATED \| "
    r"parent=(?P<parent>[^\[]+)\[(?P<ppid>\d+)\] "
    r"child=(?P<child>[^\[]+)\[(?P<pid>\d+)\]"
)


def get_username(pid):
    try:
        stat = os.stat(f"/proc/{pid}")
        uid = stat.st_uid

        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError:
            username = str(uid)

        return username, uid

    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return "unknown", -1


def get_executable(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")

    except (
        FileNotFoundError,
        ProcessLookupError,
        PermissionError,
        OSError
    ):
        return "unknown"


def classify(username):
    if username == "root":
        return "PRIVILEGED"

    return "NORMAL"


def write_event(match, logfile):

    parent = match.group("parent")
    ppid = int(match.group("ppid"))

    child = match.group("child")
    pid = int(match.group("pid"))

    username, uid = get_username(pid)
    executable = get_executable(pid)
    classification = classify(username)

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    event = (
        f"[{timestamp}] "
        f"[PROCESS CREATED] "
        f"parent={parent}[{ppid}] "
        f"child={child}[{pid}] "
        f"user={username} "
        f"uid={uid} "
        f"class={classification} "
        f"exe={executable}"
    )

    print(event, flush=True)

    logfile.write(event + "\n")
    logfile.flush()


def main():

    os.makedirs(PROJECT, exist_ok=True)

    print("=" * 70)
    print("KERNEL GUARDIAN v1.4")
    print("Linux Kernel Process Security Monitor")
    print("=" * 70)

    print(f"[+] Project : {PROJECT}")
    print(f"[+] Log     : {LOG_FILE}")
    print("[+] Starting kernel log monitor...")
    print()

    # journalctl -kf follows kernel messages in real time.
    process = subprocess.Popen(
        [
            "journalctl",
            "-k",
            "-f",
            "-n",
            "0",
            "--no-pager"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    with open(LOG_FILE, "a", buffering=1) as logfile:

        for line in process.stdout:

            match = PATTERN.search(line)

            if match:
                write_event(match, logfile)


if __name__ == "__main__":
    main()

PY

chmod +x "$COLLECTOR_DIR/guardian_collector.py"

# ------------------------------------------------------------
# 5. Fix ownership again
# ------------------------------------------------------------

chown -R "$USER_NAME:$USER_NAME" "$PROJECT"

# ------------------------------------------------------------
# 6. Remove old module
# ------------------------------------------------------------

echo
echo "[+] Removing old Kernel Guardian module..."

sudo rmmod guardian_main 2>/dev/null || true

# ------------------------------------------------------------
# 7. Build module
# ------------------------------------------------------------

echo
echo "[+] Building Kernel Guardian..."

cd "$KERNEL_DIR"

make clean
make

# ------------------------------------------------------------
# 8. Sign module if MOK exists
# ------------------------------------------------------------

if [ -f "$KERNEL_DIR/MOK.priv" ] &&
   [ -f "$KERNEL_DIR/MOK.der" ]; then

    echo "[+] Signing kernel module..."

    sudo kmodsign sha512 \
        "$KERNEL_DIR/MOK.priv" \
        "$KERNEL_DIR/MOK.der" \
        "$KERNEL_DIR/guardian_main.ko"

else

    echo "[!] MOK.priv/MOK.der not found."
    echo "[!] Continuing without custom signing."

fi

# ------------------------------------------------------------
# 9. Module information
# ------------------------------------------------------------

echo
echo "===== MODULE INFO ====="

modinfo "$KERNEL_DIR/guardian_main.ko" |
grep -E \
'name|version|description|author|vermagic|signer|sig_key|sig_id' \
|| true

# ------------------------------------------------------------
# 10. Load module
# ------------------------------------------------------------

echo
echo "===== LOADING MODULE ====="

sudo insmod "$KERNEL_DIR/guardian_main.ko"

sleep 1

# ------------------------------------------------------------
# 11. Check module
# ------------------------------------------------------------

echo
echo "===== MODULE STATUS ====="

lsmod | grep guardian || true

# ------------------------------------------------------------
# 12. Check kprobe
# ------------------------------------------------------------

echo
echo "===== KPROBE STATUS ====="

sudo cat /sys/kernel/debug/kprobes/list 2>/dev/null |
grep copy_process || true

# ------------------------------------------------------------
# 13. Enable scheduler tracepoint
# ------------------------------------------------------------

TRACE="/sys/kernel/debug/tracing"

echo
echo "===== ENABLING PROCESS TRACEPOINT ====="

if [ -d "$TRACE/events/sched/sched_process_fork" ]; then

    sudo sh -c "
        echo 0 > $TRACE/tracing_on
        : > $TRACE/trace
        echo 1 > $TRACE/events/sched/sched_process_fork/enable
        echo 1 > $TRACE/tracing_on
    "

    echo "[+] sched_process_fork enabled"

else

    echo "[!] sched_process_fork tracepoint not available"

fi

# ------------------------------------------------------------
# 14. Final status
# ------------------------------------------------------------

echo
echo "============================================================"
echo "          KERNEL GUARDIAN READY"
echo "============================================================"

echo
echo "Module:"
lsmod | grep guardian || true

echo
echo "Kprobe:"
sudo cat /sys/kernel/debug/kprobes/list 2>/dev/null |
grep copy_process || true

echo
echo "Log file:"
echo "$LOG_FILE"

echo
echo "Collector:"
echo "$COLLECTOR_DIR/guardian_collector.py"

echo
echo "============================================================"
echo "Run collector with:"
echo
echo "sudo -E python3 $COLLECTOR_DIR/guardian_collector.py"
echo
echo "Then, in another terminal:"
echo
echo "bash -c 'sleep 2 & wait'"
echo "sudo bash -c 'sleep 2 & wait'"
echo
echo "View log:"
echo
echo "tail -f $LOG_FILE"
echo "============================================================"

