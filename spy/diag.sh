#!/usr/bin/env bash
# Raw diagnostic dump for the cross-thread spy (labs/downfall/spy, Stage 1).
#
# Runs VERBOSE=1 passes so the per-trial hot classes can be inspected:
#   idle, timeslice (canary 0x42 and 0x24), and smt when CPU3 is online.
# Attacker logs land in $OUT as diag-<label>.txt; victim banners next to
# them. Attacker exit codes are ignored here (the files carry them).
#
# Usage: sudo ./diag.sh
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
OUT="${OUT:-/tmp}"
ROUNDS="${ROUNDS:-4}"
TRIALS="${TRIALS:-64}"
LOADS="${LOADS:-1}"

[ "$(id -u)" -eq 0 ] || { echo "error: run as root" >&2; exit 2; }

run() {
    local label="$1" vcpu="$2" canary="$3" vpid=""

    if [ -n "$vcpu" ]; then
        CPU="$vcpu" CANARY="$canary" ./spy-victim \
            >"$OUT/diag-victim-$label.txt" 2>&1 &
        vpid=$!
        sleep 0.5
        if ! kill -0 "$vpid" 2>/dev/null; then
            echo "warn: victim not alive for $label (see diag-victim-$label.txt)"
        fi
    fi
    env CANARY="$canary" ROUNDS="$ROUNDS" TRIALS="$TRIALS" LOADS="$LOADS" \
        VERBOSE=1 ./spy >"$OUT/diag-$label.txt" 2>&1 || true
    if [ -n "$vpid" ]; then
        kill "$vpid" 2>/dev/null || true
        wait "$vpid" 2>/dev/null || true
    fi
    echo "wrote $OUT/diag-$label.txt"
}

run idle "" 0x42
run timeslice 1 0x42
run timeslice-24 1 0x24
if [ "$(cat /sys/devices/system/cpu/cpu3/online 2>/dev/null || echo 0)" = "1" ]; then
    run smt 3 0x42
    run smt-24 3 0x24
else
    echo "note: cpu3 offline; smt diagnostics skipped"
    echo "      enable with: echo 1 | sudo tee /sys/devices/system/cpu/cpu3/online"
fi
ls -l "$OUT"/diag-*.txt
