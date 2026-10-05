#!/usr/bin/env bash
# Reload the freshly built helper module (BUG variant) for the Stage 2 lab.
#
# Build first (./helper_lkm/build.sh), then:
#   bash reload.sh          # byte page: secret_byte=0x47 (matrix arms)
#   bash reload.sh text     # built-in text page (reconstruct.sh walk)
set -eu

cd "$(dirname "$0")"

PAGE="${1:-byte}"

if ! sudo rmmod gds_helper_lkm 2>/dev/null; then
    echo "rmmod failed; killing stray ktrigger processes..."
    sudo pkill -x ktrigger 2>/dev/null || true
    sleep 0.2
    sudo rmmod gds_helper_lkm
fi

if [ "$PAGE" = "text" ]; then
    sudo insmod variants/gds_helper_lkm-BUG.ko
else
    sudo insmod variants/gds_helper_lkm-BUG.ko secret_byte=0x47
fi
sudo dmesg | tail -2
ls -l /dev/gds_helper_lkm
