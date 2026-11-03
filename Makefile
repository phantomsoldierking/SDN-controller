# Makefile - eBPF/XDP SDN data plane
#
#   make            build xdp_prog.o
#   make check      build + static sanity checks (no root needed)
#   sudo make test  run Tests 1-3 in Mininet (eBPF/XDP mode)
#   sudo make bench run Test 4 across eBPF / kernel / OVS configurations
#   sudo make clean-net   tear down leftover Mininet / BPF state

CLANG   ?= clang
PYTHON  ?= python3
ARCH    := $(shell uname -m)
# Debian/Ubuntu keep asm/ headers under a multiarch directory
ARCH_INC := $(wildcard /usr/include/$(ARCH)-linux-gnu)

BPF_CFLAGS := -O2 -g -Wall -Wextra -target bpf \
              $(if $(ARCH_INC),-I$(ARCH_INC))

OBJ := xdp_prog.o
PIN_DIR ?= /sys/fs/bpf/sdn_dp

.PHONY: all build check test test-tc bench clean clean-net deps-debian deps-arch

all: build
build: $(OBJ)

$(OBJ): xdp_prog.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

check: $(OBJ)
	@llvm-objdump -h $(OBJ) | grep -E ' (xdp|tc|\.maps) ' >/dev/null && echo "sections: xdp tc .maps OK"
	@$(PYTHON) -m py_compile control_plane.py topology.py && echo "python: syntax OK"
	@$(PYTHON) -c "import control_plane" && echo "control_plane: struct ABI sizes OK"
	@bash -n benchmark.sh && echo "benchmark.sh: syntax OK"

test: $(OBJ)
	$(PYTHON) topology.py --mode ebpf --hook xdp --test 1,2,3

test-tc: $(OBJ)
	$(PYTHON) topology.py --mode ebpf --hook tc --test 1,2,3

bench: $(OBJ)
	./benchmark.sh

clean:
	rm -f $(OBJ)
	rm -rf __pycache__

clean-net:
	-mn -c
	-rm -rf $(PIN_DIR)

deps-debian:
	apt-get install -y clang llvm libbpf-dev libbpf1 linux-libc-dev \
	    mininet openvswitch-switch iperf3 iproute2 ethtool curl python3

deps-arch:
	pacman -S --needed clang llvm libbpf linux-api-headers iperf3 iproute2 \
	    ethtool curl python openvswitch
	@echo "Mininet: install from AUR (mininet) or 'pip install mininet' + 'mnexec' from source"
