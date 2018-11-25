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

static inline unsigned long get_phys_addr(unsigned long pte_entry)
{
        return (((1UL << 46) - 1) & pte_entry) >> 12 << 12;
}

static inline int young_bit(unsigned long pte_entry)
{
        return 1UL << 5 & pte_entry ? 1 : 0;
}

static inline int dirty_bit(unsigned long pte_entry)
{
        return 1UL << 6 & pte_entry ? 1 : 0;
}

static inline int write_bit(unsigned long pte_entry)
{
        return 1UL << 1 & pte_entry ? 1 : 0;
}

static inline int user_bit(unsigned long pte_entry)
{
        return 1UL << 2 & pte_entry ? 1 : 0;
}

void print_pgtbl(struct expose_pgtbl_args *args)
{
        unsigned long fake_pgd;

        printf("0x%lx 0x%lx %d %d %d %d", )
        
}

int main(int argc, char **argv)
{
	struct pagetable_layout_info info;
	struct expose_pgtbl_args args;
	pid_t pid;
        unsigned long *base_addr;
        unsigned long range;
        unsigned long va_begin, va_end;

        if (argc < 3)
        	return -1;

        if (argv[1] != '-') {
                pid = argv[1];
                va_begin = argv[2];
                va_end = argv[3];
        } else {
                pid = argv[2];
                va_begin = argv[3];
                va_end = argv[4];
        }
        
        args.begin_vaddr = va_begin;
	args.end_vaddr = va_end;

        base_addr = (unsigned long *)malloc(sizeof(unsigned long) * 512);
        if (base_addr == NULL)
                return -1;
        args.fake_pgd = (unsigned long)base_addr;

        base_addr = mmap(NULL, sizeof(unsigned long) * 10 * 512,
                        PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        if (base_addr == NULL)
                return -1;
        args.fake_puds = (unsigned long)base_addr;

        base_addr = mmap(NULL, sizeof(unsigned long) * 100 * 512,
                        PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        if (base_addr == NULL)
                return -1;
        args.fake_pmds = (unsigned long)base_addr;

        base_addr = mmap(NULL, sizeof(unsigned long) * 512 * 512,
                        PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        if (base_addr == NULL)
                return -1;
        args.page_table_addr = (unsigned long)base_addr;
        
	printf("%d\n", getpid());
	res = syscall(__NR_expose_page_table, pid, &args);
	if (res < 0)
		printf("Error: %d\n", res);
        print_pgtbl(&args);

        return 0;
}

