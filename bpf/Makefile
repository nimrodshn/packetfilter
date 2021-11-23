CLANG   ?= clang
LLC     ?= llc
OPT     ?= opt
DIS     ?= llvm-dis

ARCH    ?= $(shell uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/x86/')
KERNEL  ?= /usr/src/linux

CFLAGS += \
	-O2 -g -emit-llvm                        \
	-D__KERNEL__                             \
	-D__BPF_TRACING__                        \
	-D__ASM_SYSREG_H						 \
	-Wno-unused-value                        \
	-Wno-pointer-sign                        \
	-Wno-compare-distinct-pointer-types      \
	-Wno-address-of-packed-member            \
	-Wno-tautological-compare                \
	-Wno-unknown-warning-option              \
	-Wno-gnu-variable-sized-type-not-at-end  \
	-fno-asynchronous-unwind-tables

bytecode.$(ARCH).o: bytecode.c
	$(CLANG) $(CFLAGS) -emit-llvm -c $< -o -  | \
	$(LLC) -march=bpf -filetype=obj -o $@