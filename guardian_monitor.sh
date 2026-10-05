#!/bin/bash

TRACE=/sys/kernel/debug/tracing

echo "=========================================="
echo "       KERNEL GUARDIAN v1.2"
echo "       PROCESS MONITOR"
echo "=========================================="

sudo sh -c "
echo 0 > $TRACE/tracing_on
echo > $TRACE/trace
echo 1 > $TRACE/events/sched/sched_process_fork/enable
echo 1 > $TRACE/tracing_on
"

echo
echo "Monitoring process creation..."
echo "Press Ctrl+C to stop."
echo

cleanup() {
    sudo sh -c "
        echo 0 > $TRACE/tracing_on
        echo 0 > $TRACE/events/sched/sched_process_fork/enable
    "
    echo
    echo "KERNEL GUARDIAN: monitoring stopped"
}

trap cleanup EXIT INT TERM

sudo cat "$TRACE/trace_pipe" | while read -r line
do
    case "$line" in
        *sched_process_fork:*)
            echo "[KERNEL GUARDIAN] $line"
            ;;
    esac
done
