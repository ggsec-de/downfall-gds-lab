#!/usr/bin/env bash
# Cross-thread GDS spy series runner (labs/downfall/spy).
#
# Usage: sudo ./run.sh <arm> [canary]
#   arm: smt | timeslice | idle | othercore
# Env overrides: REPEAT ROUNDS TRIALS CPUA CPUV CPUV_OTHER UCPHYS OUTDIR
#                 PRINT VERBOSE LOADS ASSIST (passed to spy)
#
# Every arm runs the attacker on CPUA (default 1) as root (it maps the UC
# page through /dev/mem). The victim is a second process, pinned to the
# SMT sibling (smt), the same CPU (timeslice), another core (othercore),
# or not started (idle). Logs land in ../results with a preamble (kernel,
# binary hashes, online CPUs, governor, siblings).
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

ARM="${1:-smt}"
CANARY="${2:-0x42}"
REPEAT="${REPEAT:-1}"
ROUNDS="${ROUNDS:-8}"
TRIALS="${TRIALS:-64}"
CPUA="${CPUA:-1}"
CPUV="${CPUV:-3}"
CPUV_OTHER="${CPUV_OTHER:-0}"
UCPHYS="${UCPHYS:-0xfee00000}"
OUTDIR="${OUTDIR:-$HERE/../results}"
PRINT="${PRINT:-0}"
VERBOSE="${VERBOSE:-0}"
LOADS="${LOADS:-1}"
ASSIST="${ASSIST:-uc}"

mkdir -p "$OUTDIR"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root (sudo $0 $ARM $CANARY): the attacker maps /dev/mem" >&2
    exit 2
fi

RUNAS="${RUNAS:-${SUDO_USER:-}}"

for rep in $(seq 1 "$REPEAT"); do
    TS="$(date +%Y%m%d-%H%M%S)"
    LOG="$OUTDIR/spy-$ARM-${CANARY#0x}-r$rep-$TS.txt"

    {
        echo "== spy run arm=$ARM canary=$CANARY rep=$rep started=$(date -Is)"
        echo "uname: $(uname -r)"
        echo "sha256 spy:        $(sha256sum ./spy | awk '{print $1}')"
        echo "sha256 spy-victim: $(sha256sum ./spy-victim | awk '{print $1}')"
        echo "online: $(cat /sys/devices/system/cpu/online)"
        echo "gov cpu$CPUA: $(cat /sys/devices/system/cpu/cpu$CPUA/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
        echo "sib cpu$CPUA: $(cat /sys/devices/system/cpu/cpu$CPUA/topology/thread_siblings_list 2>/dev/null || echo n/a)"
        echo "ucphys: $UCPHYS"
        echo "mode: PRINT=$PRINT VERBOSE=$VERBOSE LOADS=$LOADS"
        echo "assist: $ASSIST"
        echo "--"
    } > "$LOG"

    case "$ARM" in
        smt)       VC="$CPUV" ;;
        timeslice) VC="$CPUA" ;;
        idle)      VC="" ;;
        othercore) VC="$CPUV_OTHER" ;;
        *) echo "unknown arm: $ARM" >&2; exit 2 ;;
    esac

    VPID=""
    if [ -n "$VC" ]; then
        if [ -n "$RUNAS" ] && command -v runuser >/dev/null 2>&1; then
            runuser -u "$RUNAS" -- env CPU="$VC" CANARY="$CANARY" ./spy-victim \
                >"$OUTDIR/victim-$ARM-$TS.txt" 2>&1 &
        else
            CPU="$VC" CANARY="$CANARY" ./spy-victim \
                >"$OUTDIR/victim-$ARM-$TS.txt" 2>&1 &
        fi
        VPID=$!
        sleep 0.5
        if ! kill -0 "$VPID" 2>/dev/null; then
            echo "warn: victim not alive after 0.5s; arm degraded (see victim-$ARM-$TS.txt)" >> "$LOG"
        fi
    fi

    set +e
    CPU="$CPUA" CANARY="$CANARY" ROUNDS="$ROUNDS" TRIALS="$TRIALS" \
        UCPHYS="$UCPHYS" PRINT="$PRINT" VERBOSE="$VERBOSE" LOADS="$LOADS" \
        ASSIST="$ASSIST" ./spy >>"$LOG" 2>&1
    RC=$?
    set -e

    if [ -n "$VPID" ]; then
        kill "$VPID" 2>/dev/null || true
        wait "$VPID" 2>/dev/null || true
    fi

    echo "exit=$RC" >> "$LOG"
    echo "wrote $LOG (attacker exit=$RC)"
done
