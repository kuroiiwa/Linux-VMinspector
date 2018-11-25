#ifndef _LINUX_PGTABLE_REMAP_H
#define _LINUX_PGTABLE_REMAP_H

#include <linux/types.h>

struct pagetable_layout_info {
	uint32_t pgdir_shift;
	uint32_t pud_shift;
	uint32_t pmd_shift;
	uint32_t page_shift;
};

struct expose_pgtbl_args {
	unsigned long fake_pgd;
	unsigned long fake_puds;
	unsigned long fake_pmds;
	unsigned long page_table_addr;
	unsigned long begin_vaddr;
	unsigned long end_vaddr;
};

#endif
