#!/usr/bin/env bash
# Build gds_helper_lkm.ko for all three gadget variants.
#
# The module file name is the same for every variant. kbuild's
# external-module clean removes *.ko recursively inside the module
# directory, so the copies live one level up, outside its reach; load the
# one under test with (from this directory):
#   sudo insmod ../variants/gds_helper_lkm-BUG.ko [secret_byte=0x47|...]
set -eu

cd "$(dirname "$0")"
mkdir -p ../variants

for v in SAFE SAFEZ BUG; do
	make clean >/dev/null
	make GDS_GADGET="$v" >/dev/null
	cp gds_helper_lkm.ko "../variants/gds_helper_lkm-$v.ko"
	echo "built ../variants/gds_helper_lkm-$v.ko"
done
make clean >/dev/null
ls -l ../variants/gds_helper_lkm-*.ko
