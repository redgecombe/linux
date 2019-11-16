/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_MMU_H
#define __KVM_X86_MMU_H

#include <linux/kvm_host.h>
#include "kvm_cache_regs.h"
#include "cpuid.h"

#define PT64_PT_BITS 9
#define PT64_ENT_PER_PAGE (1 << PT64_PT_BITS)
#define PT32_PT_BITS 10
#define PT32_ENT_PER_PAGE (1 << PT32_PT_BITS)

#define PT_WRITABLE_SHIFT 1
#define PT_USER_SHIFT 2

#define PT_PRESENT_MASK (1ULL << 0)
#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_USER_MASK (1ULL << PT_USER_SHIFT)
#define PT_PWT_MASK (1ULL << 3)
#define PT_PCD_MASK (1ULL << 4)
#define PT_ACCESSED_SHIFT 5
#define PT_ACCESSED_MASK (1ULL << PT_ACCESSED_SHIFT)
#define PT_DIRTY_SHIFT 6
#define PT_DIRTY_MASK (1ULL << PT_DIRTY_SHIFT)
#define PT_PAGE_SIZE_SHIFT 7
#define PT_PAGE_SIZE_MASK (1ULL << PT_PAGE_SIZE_SHIFT)
#define PT_PAT_MASK (1ULL << 7)
#define PT_GLOBAL_MASK (1ULL << 8)
#define PT64_NX_SHIFT 63
#define PT64_NX_MASK (1ULL << PT64_NX_SHIFT)

#define PT_PAT_SHIFT 7
#define PT_DIR_PAT_SHIFT 12
#define PT_DIR_PAT_MASK (1ULL << PT_DIR_PAT_SHIFT)

#define PT32_DIR_PSE36_SIZE 4
#define PT32_DIR_PSE36_SHIFT 13
#define PT32_DIR_PSE36_MASK \
	(((1ULL << PT32_DIR_PSE36_SIZE) - 1) << PT32_DIR_PSE36_SHIFT)

#define PT64_ROOT_5LEVEL 5
#define PT64_ROOT_4LEVEL 4
#define PT32_ROOT_LEVEL 2
#define PT32E_ROOT_LEVEL 3

static inline u64 rsvd_bits(int s, int e)
{
	if (e < s)
		return 0;

	return ((1ULL << (e - s + 1)) - 1) << s;
}

void kvm_mmu_set_mmio_spte_mask(u64 mmio_value, u64 access_mask);

void
reset_shadow_zero_bits_mask(struct kvm_vcpu *vcpu, struct kvm_mmu *context);

void kvm_init_mmu(struct kvm_vcpu *vcpu, bool reset_roots);
void kvm_init_shadow_npt_mmu(struct kvm_vcpu *vcpu, u32 cr0, u32 cr4, u32 efer,
			     gpa_t nested_cr3);
void kvm_init_shadow_ept_mmu(struct kvm_vcpu *vcpu, bool execonly,
			     bool accessed_dirty, gpa_t new_eptp);
bool kvm_can_do_async_pf(struct kvm_vcpu *vcpu);
int kvm_handle_page_fault(struct kvm_vcpu *vcpu, u64 error_code,
				u64 fault_address, char *insn, int insn_len);

static inline int kvm_mmu_reload(struct kvm_vcpu *vcpu)
{
	if (likely(vcpu->arch.mmu->root_hpa != INVALID_PAGE))
		return 0;

	return kvm_mmu_load(vcpu);
}

static inline unsigned long kvm_get_pcid(struct kvm_vcpu *vcpu, gpa_t cr3)
{
	BUILD_BUG_ON((X86_CR3_PCID_MASK & PAGE_MASK) != 0);

	return kvm_read_cr4_bits(vcpu, X86_CR4_PCIDE)
	       ? cr3 & X86_CR3_PCID_MASK
	       : 0;
}

static inline unsigned long kvm_get_active_pcid(struct kvm_vcpu *vcpu)
{
	return kvm_get_pcid(vcpu, kvm_read_cr3(vcpu));
}

static inline void kvm_mmu_load_pgd(struct kvm_vcpu *vcpu)
{
	u64 root_hpa = vcpu->arch.mmu->root_hpa;

	if (!VALID_PAGE(root_hpa))
		return;

	kvm_x86_ops.load_mmu_pgd(vcpu, root_hpa | kvm_get_active_pcid(vcpu),
				 vcpu->arch.mmu->shadow_root_level);
}

int kvm_tdp_page_fault(struct kvm_vcpu *vcpu, gpa_t gpa, u32 error_code,
		       bool prefault);

static inline int kvm_mmu_do_page_fault(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
					u32 err, bool prefault)
{
#ifdef CONFIG_RETPOLINE
	if (likely(vcpu->arch.mmu->page_fault == kvm_tdp_page_fault))
		return kvm_tdp_page_fault(vcpu, cr2_or_gpa, err, prefault);
#endif
	return vcpu->arch.mmu->page_fault(vcpu, cr2_or_gpa, err, prefault);
}

/*
 * Currently, we have two sorts of write-protection, a) the first one
 * write-protects guest page to sync the guest modification, b) another one is
 * used to sync dirty bitmap when we do KVM_GET_DIRTY_LOG. The differences
 * between these two sorts are:
 * 1) the first case clears SPTE_MMU_WRITEABLE bit.
 * 2) the first case requires flushing tlb immediately avoiding corrupting
 *    shadow page table between all vcpus so it should be in the protection of
 *    mmu-lock. And the another case does not need to flush tlb until returning
 *    the dirty bitmap to userspace since it only write-protects the page
 *    logged in the bitmap, that means the page in the dirty bitmap is not
 *    missed, so it can flush tlb out of mmu-lock.
 *
 * So, there is the problem: the first case can meet the corrupted tlb caused
 * by another case which write-protects pages but without flush tlb
 * immediately. In order to making the first case be aware this problem we let
 * it flush tlb if we try to write-protect a spte whose SPTE_MMU_WRITEABLE bit
 * is set, it works since another case never touches SPTE_MMU_WRITEABLE bit.
 *
 * Anyway, whenever a spte is updated (only permission and status bits are
 * changed) we need to check whether the spte with SPTE_MMU_WRITEABLE becomes
 * readonly, if that happens, we need to flush tlb. Fortunately,
 * mmu_spte_update() has already handled it perfectly.
 *
 * The rules to use SPTE_MMU_WRITEABLE and PT_WRITABLE_MASK:
 * - if we want to see if it has writable tlb entry or if the spte can be
 *   writable on the mmu mapping, check SPTE_MMU_WRITEABLE, this is the most
 *   case, otherwise
 * - if we fix page fault on the spte or do write-protection by dirty logging,
 *   check PT_WRITABLE_MASK.
 *
 * TODO: introduce APIs to split these two cases.
 */
static inline int is_writable_pte(unsigned long pte)
{
	return pte & PT_WRITABLE_MASK;
}

static inline bool is_write_protection(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr0_bits(vcpu, X86_CR0_WP);
}

#define PERM_WRITE_BIT	0
#define PERM_USER_BIT	1
#define PERM_SMAP_BIT	2
#define PERM_FETCH_BIT	3
#define PERM_READ_BIT	4

#define PERM_WRITE_MASK (1U << PERM_WRITE_BIT)
#define PERM_USER_MASK	(1U << PERM_USER_BIT)
#define PERM_SMAP_MASK	(1U << PERM_SMAP_BIT)
#define PERM_FETCH_MASK	(1U << PERM_FETCH_BIT)
#define PERM_READ_MASK	(1U << PERM_READ_BIT)
/*
 * Check if a given access (described through the I/D, W/R and U/S bits of a
 * page fault error code pfec) causes a permission fault with the given PTE
 * access rights (in ACC_* format).
 *
 * Return zero if the access does not fault; return the page fault error code
 * if the access faults.
 */
static inline u8 permission_fault(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
				  unsigned pte_access, unsigned pte_pkey,
				  unsigned pfec)
{
	int cpl = kvm_x86_ops.get_cpl(vcpu);
	unsigned long rflags = kvm_x86_ops.get_rflags(vcpu);

	/*
	 * If CPL < 3, SMAP prevention are disabled if EFLAGS.AC = 1.
	 *
	 * If CPL = 3, SMAP applies to all supervisor-mode data accesses
	 * (these are implicit supervisor accesses) regardless of the value
	 * of EFLAGS.AC.
	 *
	 * This computes (cpl < 3) && (rflags & X86_EFLAGS_AC), leaving
	 * the result in X86_EFLAGS_AC. We then insert it in place of
	 * the PFERR_RSVD_MASK bit; this bit will always be zero in pfec,
	 * but it will be one in index if SMAP checks are being overridden.
	 * It is important to keep this branchless.
	 *
	 * Relocate the bits from the pferr code such that they form a 4 bit value
	 * to keep the array size down. Bit positions are defined in PERM_X_BIT
	 * defines.
	 */
	bool smap = !!((cpl - 3) & (rflags & X86_EFLAGS_AC));
	u32 errcode = PFERR_PRESENT_MASK;
	bool fault;
	int index;

	/* Set write at bit 0, user at bit 1, fetch at bit 3 */
	BUILD_BUG_ON(PFERR_WRITE_BIT - PERM_WRITE_BIT != 1);
	BUILD_BUG_ON(PFERR_USER_BIT - PERM_USER_BIT != 1);
	BUILD_BUG_ON(PFERR_FETCH_BIT - PERM_FETCH_BIT != 1);
	index = (pfec & (PFERR_WRITE_MASK|PFERR_USER_MASK|PFERR_FETCH_MASK)) >> 1;
	/* Set smap at bit 2 */
	index |= (unsigned)smap >> PERM_SMAP_BIT;
	/* Set read at bit 4 */
	index |= (pfec & PFERR_READ_MASK) >> (PFERR_READ_BIT - PERM_READ_BIT);

	fault = (mmu->permissions[index] >> pte_access) & 1;

	WARN_ON(pfec & (PFERR_PK_MASK | PFERR_RSVD_MASK));
	if (unlikely(mmu->pkru_mask)) {
		u32 pkru_bits, offset;

		/*
		* PKRU defines 32 bits, there are 16 domains and 2
		* attribute bits per domain in pkru.  pte_pkey is the
		* index of the protection domain, so pte_pkey * 2 is
		* is the index of the first bit for the domain.
		*/
		pkru_bits = (vcpu->arch.pkru >> (pte_pkey * 2)) & 3;

		/* clear present bit, replace PFEC.RSVD with ACC_USER_MASK. */
		offset = (pfec & ~1) +
			((pte_access & PT_USER_MASK) << (PFERR_RSVD_BIT - PT_USER_SHIFT));

		pkru_bits &= mmu->pkru_mask >> offset;
		errcode |= -pkru_bits & PFERR_PK_MASK;
		fault |= (pkru_bits != 0);
	}

	return -(u32)fault & errcode;
}

void kvm_zap_gfn_range(struct kvm *kvm, gfn_t gfn_start, gfn_t gfn_end);

int kvm_arch_write_log_dirty(struct kvm_vcpu *vcpu);

int kvm_mmu_post_init_vm(struct kvm *kvm);
void kvm_mmu_pre_destroy_vm(struct kvm *kvm);

static inline void warn_on_and_strip_synthetic(u64 *error_code)
{
	/*
	 * KVM hijacks some error code bits to communicate information about the
	 * access not covered by the standard error code bits. Ensure that they
	 * are not unexpectedly set by some new CPU.
	 */
	if (WARN_ON_ONCE(*error_code & PFERR_SYNTHETIC_MASK))
		*error_code &= ~PFERR_SYNTHETIC_MASK;
}

static inline gpa_t gpa_stolen_mask(struct kvm *kvm)
{
	/* Currently there are no stolen bits in KVM */
	return 0;
}

static inline gpa_t pf_error_to_stolen(struct kvm *kvm, u32 error_code)
{
	return 0;
}

static inline u32 stolen_to_pf_error(struct kvm *kvm, gpa_t gpa)
{
	return 0;
}

/* Software reserved bits for non-leaf PTEs */
static inline gpa_t rsvd_for_page_tables(struct kvm *kvm)
{
	/* There are currently no features with rsvd bits in non-leaf ptes */
	return 0;
}

#endif
