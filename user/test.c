#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

#define __NR_get_pagetable_layout 326
#define __NR_expose_page_table 327

#define PGDIR_SHIFT		39
#define PUD_SHIFT		30
#define PMD_SHIFT		21
#define PAGE_SHIFT		12
#define PTRS_PER_PTE		512
#define PTRS_PER_PMD		512
#define PTRS_PER_PGD		512

#define pgd_index(addr)		(((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pmd_index(addr)		(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(addr)		(((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

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

void print_pgtbl(struct expose_pgtbl_args *args, unsigned long range)
{
        unsigned long *pgd_table = (unsigned long *)args->fake_pgd;
        unsigned long *pud_tables = (unsigned long *)args->fake_puds;
        unsigned long *pmd_tables = (unsigned long *)args->fake_pmds;
        unsigned long *pte_tables = (unsigned long *)args->page_table_addr;
        int total_pgd = 10;

        printf("======PGD=====\n");
        for (int i = 0; i < 512; i++) {
                if (pgd_table[i] == 0)
                        continue;
                printf("%03d|0x%016lx|\n", i, pgd_table[i]);
        }
        printf("======PUD=====\n");
        for (int i = 0; i < total_pgd; i++) {
               for (int j = 0; j < 512; j++) {
                       if (pud_tables[j] == 0)
                               continue;
                       printf("%03d->%03d|0x%016lx|\n", i, j, pud_tables[j]);
               }
               pud_tables = (unsigned long *)((unsigned long)pud_tables
                       + 512 * sizeof(unsigned long));
        }
        printf("======PMD=====\n");
        for (int i = 0; i < total_pgd; i++) {
               for (int j = 0; j < 512; j++) {
                       if (pmd_tables[j] == 0)
                               continue;
                       printf("%03d->%03d|0x%016lx|\n", i, j, pmd_tables[j]);
               }
               pmd_tables = (unsigned long *)((unsigned long)pmd_tables
                       + 512 * sizeof(unsigned long));
        }
        printf("======PTE=====\n");
        for (int i = 0; i < total_pgd; i++) {
               for (int j = 0; j < 512; j++) {
                       if (pte_tables[j] == 0)
                               continue;
                       printf("%03d->%03d|0x%016lx|\n",i ,j , pte_tables[j]);
               }
               pte_tables = (unsigned long *)((unsigned long)pte_tables
                       + 512 * sizeof(unsigned long));
        }
}

int main(int argc, char **argv)
{
	struct pagetable_layout_info info;
	struct expose_pgtbl_args args;
	pid_t pid;
        unsigned long *base_addr;
        unsigned long range;

	int res = syscall(__NR_get_pagetable_layout, &info,
			sizeof(struct pagetable_layout_info));
        if (res)
                printf("layout: pgd[%d] pud[%d] pmd[%d] pg_shift[%d]\n",
                        info.pgdir_shift, info.pud_shift,
                        info.pmd_shift, info.page_shift);

        //args.begin_vaddr = 0x640000000000; //PGD=200
        args.begin_vaddr = 0x000000000000; //PGD=200
	args.end_vaddr = 0xffffffffffff; //VA_END

        base_addr = (unsigned long *)malloc(sizeof(unsigned long) * 512);
        if (base_addr == NULL)
                return -1;
        args.fake_pgd = (unsigned long)base_addr;

        range = pgd_index(args.end_vaddr) - pgd_index(args.begin_vaddr) + 1;

        base_addr = mmap(NULL, sizeof(unsigned long) * 10 * 512,
                        PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        if (base_addr == NULL)
                return -1;
        args.fake_puds = (unsigned long)base_addr;

        base_addr = mmap(NULL, sizeof(unsigned long) * 10 * 10 * 512,
                        PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        if (base_addr == NULL)
                return -1;
        args.fake_pmds = (unsigned long)base_addr;

        base_addr = mmap(NULL, sizeof(unsigned long) * 512 * 512,
                        PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        if (base_addr == NULL)
                return -1;
        args.page_table_addr = (unsigned long)base_addr;
        printf("%16lx\n", (unsigned long)base_addr);

        pid = 1;
	printf("%d %lu\n", getpid(), range);
	res = syscall(__NR_expose_page_table, pid, &args);
	if (res < 0)
		printf("Error[%d]\n", res);
        print_pgtbl(&args, range);
        return 0;
}
