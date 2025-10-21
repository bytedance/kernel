# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Kernel-based Virtual Machine module
#

ccflags-y += -I $(srctree)/$(src)

include $(srctree)/virt/kvm/Makefile.kvm

obj-$(CONFIG_KVM) += kvm.o

kvm-y += arm.o mmu.o mmio.o psci.o hypercalls.o pvtime.o \
	 inject_fault.o va_layout.o handle_exit.o \
	 guest.o debug.o reset.o sys_regs.o \
	 vgic-sys-reg-v3.o fpsimd.o \
	 arch_timer.o trng.o vmid.o emulate-nested.o nested.o \
	 vgic/vgic.o vgic/vgic-init.o \
	 vgic/vgic-irqfd.o vgic/vgic-v2.o \
	 vgic/vgic-v3.o vgic/vgic-v4.o \
	 vgic/vgic-mmio.o vgic/vgic-mmio-v2.o \
	 vgic/vgic-mmio-v3.o vgic/vgic-kvm-device.o \
	 vgic/vgic-its.o vgic/vgic-debug.o

kvm-$(CONFIG_VIRT_PLAT_DEV)  += vgic/shadow_dev.o
kvm-$(CONFIG_HW_PERF_EVENTS)  += pmu-emul.o pmu.o

# build kvm as in-tree module
ifeq ($(CONFIG_KVM), y)
obj-$(CONFIG_KVM) += hyp/
obj-$(CONFIG_KVM_HISI_VIRT) += hisilicon/

kvm-y += pkvm.o stacktrace.o

always-y := hyp_constants.h hyp-constants.s

define rule_gen_hyp_constants
	$(call filechk,offsets,__HYP_CONSTANTS_H__)
endef

CFLAGS_hyp-constants.o = -I $(srctree)/$(src)/hyp/include
$(obj)/hyp-constants.s: $(src)/hyp/hyp-constants.c FORCE
	$(call if_changed_dep,cc_s_c)

$(obj)/hyp_constants.h: $(obj)/hyp-constants.s FORCE
	$(call if_changed_rule,gen_hyp_constants)

obj-kvm := $(addprefix $(obj)/, $(kvm-y))
$(obj-kvm): $(obj)/hyp_constants.h

# build kvm as out-of-tree module
else
hyp_incdir := $(srctree)/$(src)/hyp/include

kvm-y += hyp/pgtable.o
kvm_hyp :=  $(addprefix hyp/, vgic-v3-sr.o aarch32.o vgic-v2-cpuif-proxy.o entry.o \
                  fpsimd.o hyp-entry.o exception.o)
kvm_hyp += $(addprefix hyp/vhe/, timer-sr.o sysreg-sr.o debug-sr.o switch.o tlb.o)

$(foreach file, $(kvm_hyp), $(eval CFLAGS_$(file) += -I$(hyp_incdir)             \
                                                    -D__KVM_VHE_HYPERVISOR__))
$(foreach file, $(kvm_hyp), $(eval AFLAGS_$(file) += -I$(hyp_incdir) -D__KVM_VHE_HYPERVISOR__))

kvm-y += $(kvm_hyp)

ifeq ($(CONFIG_KVM_HISI_VIRT), y)
kvm-y += hisilicon/hisi_virt.o
endif
endif
