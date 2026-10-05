#!/usr/bin/env bash
# Stage 2 quick test matrix: (trigger, attacker) pairs, logs to /tmp/kt-<label>.log.
#
# Usage (as the normal user, from this directory):
#   bash reload.sh            # (re)load the module
#   bash matrix.sh            # quick pass (ROUNDS=2)
#   ROUNDS=8 bash matrix.sh   # series pass for the record
# Each run writes /tmp/kt-<label>-<HHMMSS>.log.
# The trigger runs as this user; the attacker call uses sudo (it maps
# /dev/mem). Pull /tmp/kt-*.log afterwards for analysis.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ ! -e /dev/gds_helper_lkm ]; then
    echo "error: /dev/gds_helper_lkm not present; load the module first:" >&2
    echo "  bash reload.sh" >&2
    exit 2
fi

if ! env CPU=3 ITERS=1 MODE=kcopy KOP=movsb OFFSET=0 LEN=16 ./ktrigger \
        >/tmp/kt-probe.log 2>&1; then
    echo "error: KREPMOV probe failed; see /tmp/kt-probe.log; reload the module:" >&2
    echo "  bash reload.sh" >&2
    exit 2
fi

ROUNDS="${ROUNDS:-2}"
TRIALS="${TRIALS:-64}"

run_pair() {
    local label="$1" tri="$2" canary="$3" tcp="$4"
    local log="/tmp/kt-$label-$(date +%H%M%S).log"
    local kp rc

    : >"$log"
    echo "== $label :: CPU=$tcp $tri (canary=$canary)" | tee -a "$log"
    env CPU="$tcp" $tri ./ktrigger >>"$log" 2>&1 &
    kp=$!
    sleep 0.3
    sudo env CPU=1 CANARY="$canary" ROUNDS="$ROUNDS" TRIALS="$TRIALS" \
        LOADS=4 ../spy/spy >>"$log" 2>&1
    rc=$?
    kill "$kp" 2>/dev/null
    wait "$kp" 2>/dev/null
    echo "spy_rc=$rc" >>"$log"
    tail -16 "$log"
    echo
}

run_pair t7-urepmov  "USER=0x47 REPMOV=1" 0x47 3
run_pair t8-krep     "MODE=krep OFFSET=0x1000 LEN=4095" 0x47 3
run_pair t11-kcmovsb "MODE=kcopy KOP=movsb OFFSET=0x1000 LEN=4095" 0x47 3
run_pair t12-kcmovsq "MODE=kcopy KOP=movsq OFFSET=0x1000 LEN=4096" 0x47 3
run_pair t13-kcstosb "MODE=kcopy KOP=stosb OFFSET=0x1000 LEN=4095 KAL=0x47" 0x47 3
run_pair t14-kcscalar "MODE=kcopy KOP=scalar OFFSET=0x1000 LEN=4095" 0x47 3
run_pair t9-krep1    "MODE=krep OFFSET=0x1000 LEN=4095" 0x47 1
run_pair t3-sec      "MODE=arb TARGET=secret LEN=4095" 0x47 3
