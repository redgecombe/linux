/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_SET_MEMORY_H
#define __ASM_SET_MEMORY_H

/*
 * Functions to change memory attributes.
 */
int set_memory_ro(unsigned long addr, int numpages);
int set_memory_rw(unsigned long addr, int numpages);
int set_memory_x(unsigned long addr, int numpages);
int set_memory_nx(unsigned long addr, int numpages);
#ifdef CONFIG_ARCH_HAS_NR
int set_memory_r(unsigned long addr, int numpages);
int set_memory_nr(unsigned long addr, int numpages);
#else
static inline int set_memory_r(unsigned long addr, int numpages) { return 0; }
static inline int set_memory_nr(unsigned long addr, int numpages) { return 0; }
#endif /* CONFIG_ARCH_HAS_NR */
#endif
