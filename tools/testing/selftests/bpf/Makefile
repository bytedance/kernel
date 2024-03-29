# SPDX-License-Identifier: GPL-2.0
include ../../../../scripts/Kbuild.include
include ../../../scripts/Makefile.arch

CXX ?= $(CROSS_COMPILE)g++
LIBDIR := ../../../lib
BPFDIR := $(LIBDIR)/bpf
APIDIR := ../../../include/uapi
GENDIR := ../../../../include/generated
GENHDR := $(GENDIR)/autoconf.h

ifneq ($(wildcard $(GENHDR)),)
  GENFLAGS := -DHAVE_GENHDR
endif

CLANG		?= clang
LLC		?= llc
LLVM_OBJCOPY	?= llvm-objcopy
LLVM_READELF	?= llvm-readelf
BTF_PAHOLE	?= pahole
BPF_GCC		?= $(shell command -v bpf-gcc;)
CFLAGS += -g -Wall -O2 -I$(APIDIR) -I$(LIBDIR) -I$(BPFDIR) -I$(GENDIR) $(GENFLAGS) -I../../../include \
	  -Dbpf_prog_load=bpf_prog_test_load \
	  -Dbpf_load_program=bpf_test_load_program
LDLIBS += -lcap -lelf -lrt -lpthread

# Order correspond to 'make run_tests' order
TEST_GEN_PROGS = test_verifier test_tag test_maps test_lru_map test_lpm_map test_progs \
	test_align test_verifier_log test_dev_cgroup test_tcpbpf_user \
	test_sock test_btf test_sockmap get_cgroup_id_user test_socket_cookie \
	test_cgroup_storage test_select_reuseport test_section_names \
	test_netcnt test_tcpnotify_user test_sock_fields test_sysctl test_hashmap \
	test_btf_dump test_cgroup_attach xdping

BPF_OBJ_FILES = $(patsubst %.c,%.o, $(notdir $(wildcard progs/*.c)))
TEST_GEN_FILES = $(BPF_OBJ_FILES)

BTF_C_FILES = $(wildcard progs/btf_dump_test_case_*.c)
TEST_FILES = $(BTF_C_FILES)

# Also test sub-register code-gen if LLVM has eBPF v3 processor support which
# contains both ALU32 and JMP32 instructions.
SUBREG_CODEGEN := $(shell echo "int cal(int a) { return a > 0; }" | \
			$(CLANG) -target bpf -O2 -emit-llvm -S -x c - -o - | \
			$(LLC) -mattr=+alu32 -mcpu=v3 2>&1 | \
			grep 'if w')
ifneq ($(SUBREG_CODEGEN),)
TEST_GEN_FILES += $(patsubst %.o,alu32/%.o, $(BPF_OBJ_FILES))
endif

ifneq ($(BPF_GCC),)
TEST_GEN_FILES += $(patsubst %.o,bpf_gcc/%.o, $(BPF_OBJ_FILES))
endif

# Order correspond to 'make run_tests' order
TEST_PROGS := test_kmod.sh \
	test_libbpf.sh \
	test_xdp_redirect.sh \
	test_xdp_meta.sh \
	test_xdp_veth.sh \
	test_offload.py \
	test_sock_addr.sh \
	test_tunnel.sh \
	test_lwt_seg6local.sh \
	test_lirc_mode2.sh \
	test_skb_cgroup_id.sh \
	test_flow_dissector.sh \
	test_xdp_vlan_mode_generic.sh \
	test_xdp_vlan_mode_native.sh \
	test_lwt_ip_encap.sh \
	test_tcp_check_syncookie.sh \
	test_tc_tunnel.sh \
	test_tc_edt.sh \
	test_xdping.sh \
	test_bpftool_build.sh

TEST_PROGS_EXTENDED := with_addr.sh \
	with_tunnels.sh \
	tcp_client.py \
	tcp_server.py \
	test_xdp_vlan.sh

# Compile but not part of 'make run_tests'
TEST_GEN_PROGS_EXTENDED = test_libbpf_open test_sock_addr test_skb_cgroup_id_user \
	flow_dissector_load test_flow_dissector test_tcp_check_syncookie_user \
	test_lirc_mode2_user

include ../lib.mk

# NOTE: $(OUTPUT) won't get default value if used before lib.mk
TEST_CUSTOM_PROGS = $(OUTPUT)/urandom_read
all: $(TEST_CUSTOM_PROGS)

$(OUTPUT)/urandom_read: $(OUTPUT)/%: %.c
	$(CC) -o $@ $< -Wl,--build-id

$(OUTPUT)/test_stub.o: test_stub.c
	$(CC) $(TEST_PROGS_CFLAGS) $(CFLAGS) -c -o $@ $<

BPFOBJ := $(OUTPUT)/libbpf.a

$(TEST_GEN_PROGS): $(OUTPUT)/test_stub.o $(BPFOBJ)

$(TEST_GEN_PROGS_EXTENDED): $(OUTPUT)/test_stub.o $(OUTPUT)/libbpf.a

$(OUTPUT)/test_dev_cgroup: cgroup_helpers.c
$(OUTPUT)/test_skb_cgroup_id_user: cgroup_helpers.c
$(OUTPUT)/test_sock: cgroup_helpers.c
$(OUTPUT)/test_sock_addr: cgroup_helpers.c
$(OUTPUT)/test_socket_cookie: cgroup_helpers.c
$(OUTPUT)/test_sockmap: cgroup_helpers.c
$(OUTPUT)/test_tcpbpf_user: cgroup_helpers.c
$(OUTPUT)/test_tcpnotify_user: cgroup_helpers.c trace_helpers.c
$(OUTPUT)/test_progs: cgroup_helpers.c trace_helpers.c
$(OUTPUT)/get_cgroup_id_user: cgroup_helpers.c
$(OUTPUT)/test_cgroup_storage: cgroup_helpers.c
$(OUTPUT)/test_netcnt: cgroup_helpers.c
$(OUTPUT)/test_sock_fields: cgroup_helpers.c
$(OUTPUT)/test_sysctl: cgroup_helpers.c
$(OUTPUT)/test_cgroup_attach: cgroup_helpers.c

.PHONY: force

# force a rebuild of BPFOBJ when its dependencies are updated
force:

$(BPFOBJ): force
	$(MAKE) -C $(BPFDIR) OUTPUT=$(OUTPUT)/

PROBE := $(shell $(LLC) -march=bpf -mcpu=probe -filetype=null /dev/null 2>&1)

# Let newer LLVM versions transparently probe the kernel for availability
# of full BPF instruction set.
ifeq ($(PROBE),)
  CPU ?= probe
else
  CPU ?= generic
endif

# Get Clang's default includes on this system, as opposed to those seen by
# '-target bpf'. This fixes "missing" files on some architectures/distros,
# such as asm/byteorder.h, asm/socket.h, asm/sockios.h, sys/cdefs.h etc.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
define get_sys_includes
$(shell $(1) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') \
$(shell $(1) -dM -E - </dev/null | grep '#define __riscv_xlen ' | sed 's/#define /-D/' | sed 's/ /=/')
endef
CLANG_SYS_INCLUDES = $(call get_sys_includes,$(CLANG))
BPF_CFLAGS = -I. -I./include/uapi -I../../../include/uapi \
	     -I$(OUTPUT)/../usr/include -D__TARGET_ARCH_$(SRCARCH)

CLANG_CFLAGS = $(CLANG_SYS_INCLUDES) \
	       -Wno-compare-distinct-pointer-types

$(OUTPUT)/test_l4lb_noinline.o: BPF_CFLAGS += -fno-inline
$(OUTPUT)/test_xdp_noinline.o: BPF_CFLAGS += -fno-inline

$(OUTPUT)/test_queue_map.o: test_queue_stack_map.h
$(OUTPUT)/test_stack_map.o: test_queue_stack_map.h

$(OUTPUT)/flow_dissector_load.o: flow_dissector_load.h
$(OUTPUT)/test_progs.o: flow_dissector_load.h

BTF_LLC_PROBE := $(shell $(LLC) -march=bpf -mattr=help 2>&1 | grep dwarfris)
BTF_PAHOLE_PROBE := $(shell $(BTF_PAHOLE) --help 2>&1 | grep BTF)
BTF_OBJCOPY_PROBE := $(shell $(LLVM_OBJCOPY) --help 2>&1 | grep -i 'usage.*llvm')
BTF_LLVM_PROBE := $(shell echo "int main() { return 0; }" | \
			  $(CLANG) -target bpf -O2 -g -c -x c - -o ./llvm_btf_verify.o; \
			  $(LLVM_READELF) -S ./llvm_btf_verify.o | grep BTF; \
			  /bin/rm -f ./llvm_btf_verify.o)

ifneq ($(BTF_LLVM_PROBE),)
	BPF_CFLAGS += -g
else
ifneq ($(BTF_LLC_PROBE),)
ifneq ($(BTF_PAHOLE_PROBE),)
ifneq ($(BTF_OBJCOPY_PROBE),)
	BPF_CFLAGS += -g
	LLC_FLAGS += -mattr=dwarfris
	DWARF2BTF = y
endif
endif
endif
endif

TEST_PROGS_CFLAGS := -I. -I$(OUTPUT)
TEST_MAPS_CFLAGS := -I. -I$(OUTPUT)
TEST_VERIFIER_CFLAGS := -I. -I$(OUTPUT) -Iverifier

ifneq ($(SUBREG_CODEGEN),)
ALU32_BUILD_DIR = $(OUTPUT)/alu32
TEST_CUSTOM_PROGS += $(ALU32_BUILD_DIR)/test_progs_32
$(ALU32_BUILD_DIR):
	mkdir -p $@

$(ALU32_BUILD_DIR)/urandom_read: $(OUTPUT)/urandom_read | $(ALU32_BUILD_DIR)
	cp $< $@

$(ALU32_BUILD_DIR)/test_progs_32: test_progs.c $(OUTPUT)/libbpf.a\
						$(ALU32_BUILD_DIR)/urandom_read \
						| $(ALU32_BUILD_DIR)
	$(CC) $(TEST_PROGS_CFLAGS) $(CFLAGS) \
		-o $(ALU32_BUILD_DIR)/test_progs_32 \
		test_progs.c test_stub.c cgroup_helpers.c trace_helpers.c prog_tests/*.c \
		$(OUTPUT)/libbpf.a $(LDLIBS)

$(ALU32_BUILD_DIR)/test_progs_32: $(PROG_TESTS_H)
$(ALU32_BUILD_DIR)/test_progs_32: prog_tests/*.c

$(ALU32_BUILD_DIR)/%.o: progs/%.c $(ALU32_BUILD_DIR)/test_progs_32 \
					| $(ALU32_BUILD_DIR)
	($(CLANG) $(BPF_CFLAGS) $(CLANG_CFLAGS) -O2 -target bpf -emit-llvm \
		-c $< -o - || echo "clang failed") | \
	$(LLC) -march=bpf -mattr=+alu32 -mcpu=$(CPU) $(LLC_FLAGS) \
		-filetype=obj -o $@
ifeq ($(DWARF2BTF),y)
	$(BTF_PAHOLE) -J $@
endif
endif

ifneq ($(BPF_GCC),)
GCC_SYS_INCLUDES = $(call get_sys_includes,gcc)
IS_LITTLE_ENDIAN = $(shell $(CC) -dM -E - </dev/null | \
			grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')
ifeq ($(IS_LITTLE_ENDIAN),)
MENDIAN=-mbig-endian
else
MENDIAN=-mlittle-endian
endif
BPF_GCC_CFLAGS = $(GCC_SYS_INCLUDES) $(MENDIAN)
BPF_GCC_BUILD_DIR = $(OUTPUT)/bpf_gcc
TEST_CUSTOM_PROGS += $(BPF_GCC_BUILD_DIR)/test_progs_bpf_gcc
$(BPF_GCC_BUILD_DIR):
	mkdir -p $@

$(BPF_GCC_BUILD_DIR)/urandom_read: $(OUTPUT)/urandom_read | $(BPF_GCC_BUILD_DIR)
	cp $< $@

$(BPF_GCC_BUILD_DIR)/test_progs_bpf_gcc: $(OUTPUT)/test_progs \
					 | $(BPF_GCC_BUILD_DIR)
	cp $< $@

$(BPF_GCC_BUILD_DIR)/%.o: progs/%.c $(BPF_GCC_BUILD_DIR)/test_progs_bpf_gcc \
			  | $(BPF_GCC_BUILD_DIR)
	$(BPF_GCC) $(BPF_CFLAGS) $(BPF_GCC_CFLAGS) -O2 -c $< -o $@
endif

# Have one program compiled without "-target bpf" to test whether libbpf loads
# it successfully
$(OUTPUT)/test_xdp.o: progs/test_xdp.c
	($(CLANG) $(BPF_CFLAGS) $(CLANG_CFLAGS) -O2 -emit-llvm -c $< -o - || \
		echo "clang failed") | \
	$(LLC) -march=bpf -mcpu=$(CPU) $(LLC_FLAGS) -filetype=obj -o $@
ifeq ($(DWARF2BTF),y)
	$(BTF_PAHOLE) -J $@
endif

$(OUTPUT)/%.o: progs/%.c
	($(CLANG) $(BPF_CFLAGS) $(CLANG_CFLAGS) -O2 -target bpf -emit-llvm \
		-c $< -o - || echo "clang failed") | \
	$(LLC) -march=bpf -mcpu=$(CPU) $(LLC_FLAGS) -filetype=obj -o $@
ifeq ($(DWARF2BTF),y)
	$(BTF_PAHOLE) -J $@
endif

PROG_TESTS_DIR = $(OUTPUT)/prog_tests
$(PROG_TESTS_DIR):
	mkdir -p $@
PROG_TESTS_H := $(PROG_TESTS_DIR)/tests.h
PROG_TESTS_FILES := $(wildcard prog_tests/*.c)
test_progs.c: $(PROG_TESTS_H)
$(OUTPUT)/test_progs: CFLAGS += $(TEST_PROGS_CFLAGS)
$(OUTPUT)/test_progs: test_progs.c $(PROG_TESTS_FILES) | $(PROG_TESTS_H)
$(PROG_TESTS_H): $(PROG_TESTS_FILES) | $(PROG_TESTS_DIR)
	$(shell ( cd prog_tests/; \
		  echo '/* Generated header, do not edit */'; \
		  ls *.c 2> /dev/null | \
			sed -e 's@\([^\.]*\)\.c@DEFINE_TEST(\1)@'; \
		 ) > $(PROG_TESTS_H))

MAP_TESTS_DIR = $(OUTPUT)/map_tests
$(MAP_TESTS_DIR):
	mkdir -p $@
MAP_TESTS_H := $(MAP_TESTS_DIR)/tests.h
MAP_TESTS_FILES := $(wildcard map_tests/*.c)
test_maps.c: $(MAP_TESTS_H)
$(OUTPUT)/test_maps: CFLAGS += $(TEST_MAPS_CFLAGS)
$(OUTPUT)/test_maps: test_maps.c $(MAP_TESTS_FILES) | $(MAP_TESTS_H)
$(MAP_TESTS_H): $(MAP_TESTS_FILES) | $(MAP_TESTS_DIR)
	$(shell ( cd map_tests/; \
		  echo '/* Generated header, do not edit */'; \
		  echo '#ifdef DECLARE'; \
		  ls *.c 2> /dev/null | \
			sed -e 's@\([^\.]*\)\.c@extern void test_\1(void);@'; \
		  echo '#endif'; \
		  echo '#ifdef CALL'; \
		  ls *.c 2> /dev/null | \
			sed -e 's@\([^\.]*\)\.c@test_\1();@'; \
		  echo '#endif' \
		 ) > $(MAP_TESTS_H))

VERIFIER_TESTS_DIR = $(OUTPUT)/verifier
$(VERIFIER_TESTS_DIR):
	mkdir -p $@
VERIFIER_TESTS_H := $(VERIFIER_TESTS_DIR)/tests.h
VERIFIER_TEST_FILES := $(wildcard verifier/*.c)
test_verifier.c: $(VERIFIER_TESTS_H)
$(OUTPUT)/test_verifier: CFLAGS += $(TEST_VERIFIER_CFLAGS)
$(OUTPUT)/test_verifier: test_verifier.c | $(VERIFIER_TEST_FILES) $(VERIFIER_TESTS_H)
$(VERIFIER_TESTS_H): $(VERIFIER_TEST_FILES) | $(VERIFIER_TESTS_DIR)
	$(shell ( cd verifier/; \
		  echo '/* Generated header, do not edit */'; \
		  echo '#ifdef FILL_ARRAY'; \
		  ls *.c 2> /dev/null | \
			sed -e 's@\(.*\)@#include \"\1\"@'; \
		  echo '#endif' \
		 ) > $(VERIFIER_TESTS_H))

EXTRA_CLEAN := $(TEST_CUSTOM_PROGS) $(ALU32_BUILD_DIR) $(BPF_GCC_BUILD_DIR) \
	$(VERIFIER_TESTS_H) $(PROG_TESTS_H) $(MAP_TESTS_H) \
	feature
