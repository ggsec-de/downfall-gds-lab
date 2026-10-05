# kbuild for the GDS kernel-leak helper (Downfall lab, Stage 2).
#
# Build all variants:   ./build.sh
# Build one variant:    make GDS_GADGET=SAFE   (SAFE | SAFEZ | BUG)
# Clean:                make clean
obj-m := gds_helper_lkm.o
GDS_GADGET ?= SAFE
ccflags-y += -DKERNEL_GADGET_$(GDS_GADGET)

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$$PWD modules

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
