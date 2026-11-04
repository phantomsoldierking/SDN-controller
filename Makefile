# Makefile - eBPF/XDP SDN data plane
#
#   make                 build build/xdp_prog.o
#   make check           build + unit tests + static checks (no root needed)
#   make unittest        control-plane unit tests (no root needed)
#   sudo make test-bpf   kernel data-plane tests via BPF_PROG_TEST_RUN (no Mininet)
#   sudo make test       Mininet Tests 1-3, XDP hook
#   sudo make test-tc    Mininet Tests 1-3, TC hook
#   sudo make bench      Test 4 across eBPF / kernel / OVS configurations
#   sudo make clean-net  tear down leftover Mininet / BPF state

CLANG   ?= clang
PYTHON  ?= python3
ARCH    := $(shell uname -m)
# Debian/Ubuntu keep asm/ headers under a multiarch directory
ARCH_INC := $(wildcard /usr/include/$(ARCH)-linux-gnu)

BPF_CFLAGS := -O2 -g -Wall -Wextra -target bpf $(if $(ARCH_INC),-I$(ARCH_INC))
BPF_SRCS   := $(wildcard bpf/*.c bpf/*.h)
OBJ        := build/xdp_prog.o
PIN_DIR    ?= /sys/fs/bpf/sdn_dp
PY_SRCS    := control_plane.py topology.py sdn testbed tests

.PHONY: all build toolchain check unittest test-bpf test test-tc bench lint clean clean-net \
        deps-debian deps-arch

all: build
build: $(OBJ)

# Fail early, with the real cause, when the compiler itself cannot run
# (e.g. clang and llvm-libs at different versions after a partial upgrade).
toolchain:
	@$(CLANG) --version >/dev/null 2>&1 || { \
	  echo "error: '$(CLANG)' cannot run - this is a toolchain problem, not a code problem:"; \
	  $(CLANG) --version 2>&1 | head -1 | sed 's/^/    /'; \
	  echo "  A 'libLLVM.so.N' error means clang and llvm-libs are at different versions."; \
	  echo "  Compare: pacman -Q clang llvm-libs   (Debian: dpkg -l clang libllvm*)"; \
	  echo "  Fix: update the whole system (Arch: pacman -Syu, Omarchy: omarchy update)."; \
	  exit 1; }

$(OBJ): $(BPF_SRCS) | toolchain
	@mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) -c bpf/xdp_prog.c -o $@

check: $(OBJ) unittest
	@llvm-objdump -h $(OBJ) | grep -qE ' xdp ' && llvm-objdump -h $(OBJ) | grep -qE ' tc ' \
	    && echo "object: xdp + tc programs present"
	@$(PYTHON) -m compileall -q $(PY_SRCS) && echo "python: compiles"
	@bash -n benchmark.sh && echo "benchmark.sh: syntax OK"

unittest:
	$(PYTHON) -m unittest discover -s tests -t . -p 'test_*.py'

test-bpf: $(OBJ)
	$(PYTHON) -m unittest -v tests.test_bpf_dataplane

test: $(OBJ)
	$(PYTHON) topology.py --mode ebpf --hook xdp --test 1,2,3

test-tc: $(OBJ)
	$(PYTHON) topology.py --mode ebpf --hook tc --test 1,2,3

bench: $(OBJ)
	./benchmark.sh

lint:
	@command -v ruff >/dev/null && ruff check $(PY_SRCS) \
	    || $(PYTHON) -m pyflakes $(PY_SRCS)

clean:
	rm -rf build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

clean-net:
	-mn -c
	-rm -rf $(PIN_DIR)

deps-debian:
	apt-get install -y clang llvm libbpf-dev libbpf1 linux-libc-dev \
	    mininet openvswitch-switch iperf3 iproute2 ethtool curl python3

deps-arch:
	pacman -S --needed clang llvm libbpf linux-api-headers iperf3 iproute2 \
	    ethtool curl python openvswitch
	@echo "Mininet: install from the AUR (yay -S mininet)"
