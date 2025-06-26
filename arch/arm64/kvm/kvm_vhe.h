/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM64_KVM_VHE_H__
#define __ARM64_KVM_VHE_H__

#if IS_MODULE(CONFIG_KVM)
int kvm_hyp_init_protection(u32 hyp_va_bits) { return 0; }
int init_hyp_mode(void) { return 0; }
void hyp_install_host_vector(void) {  }
unsigned long nvhe_percpu_order(void) { return 0; }
void pkvm_destroy_hyp_vm(struct kvm *host_kvm) { }
int pkvm_create_hyp_vm(struct kvm *host_kvm) { return 0; }
int pkvm_init_host_vm(struct kvm *host_kvm) { return 0; }
#endif

#endif /* __ARM64_KVM_VHE_H__ */
