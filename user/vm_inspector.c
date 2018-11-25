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
#define PTRS_PER_PUD		512

#define pgd_index(addr)		(((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pmd_index(addr)		(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(addr)		(((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pud_index(addr)         (((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))

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
	unsigned long *fake_pgd = (unsigned long *)args->fake_pgd;
        unsigned long *fake_puds = (unsigned long *)args->fake_puds;
        unsigned long *fake_pmds = (unsigned long *)args->fake_pmds;
        unsigned long *page_table_addr = (unsigned long *)args->page_table_addr;
        unsigned long begin_vaddr = args->begin_vaddr;
        unsigned long end_vaddr = args->end_vaddr;
        unsigned long curr_va, p;
        unsigned long f_pgd_ent, f_pud_ent, f_pmd_ent, f_pte_ent;
        unsigned long *f_pgd_ent_p, *f_pud_ent_p, *f_pmd_ent_p, *f_pte_ent_p;
        int i = 0;
        // for (int i = 0; i < 512 * 512; i++) {
        //         if (fake_pmds[i] != 0)
        //                 printf("%lx %lx %lx %lx %lx\n", get_phys_addr(fake_pmds[i]), young_bit(fake_pmds[i]), dirty_bit(fake_pmds[i]), write_bit(fake_pmds[i]), user_bit(fake_pmds[i]) );
        //
        // }

//        for (int i = 0; i < 512; i++) {
//                f_pgd_ent = (unsigned long *)(fake_pgd + i
//                                * sizeof(unsigned long));
//                printf("%d,%lx %lx \n", i, fake_pgd[i], *f_pgd_ent);
//        }

        for (curr_va = begin_vaddr;curr_va < end_vaddr; curr_va += 4096) {
                // f_pgd_ent = (unsigned long *)(fake_pgd + pgd_index(curr_va)
                //                 * sizeof(unsigned long));
                f_pgd_ent = fake_pgd[(int)pgd_index(curr_va)];
                if (f_pgd_ent == 0){
                        curr_va += ((unsigned long)1 << 39);
                        continue;
                }

                f_pgd_ent_p = (unsigned long *)f_pgd_ent;
                f_pud_ent = f_pgd_ent_p[pud_index(curr_va)];
                if (f_pud_ent == 0) {
                         curr_va += ((unsigned long)1 << 30);
                         continue;
                }

                f_pud_ent_p = (unsigned long *)f_pud_ent;
                f_pmd_ent = f_pud_ent_p[pmd_index(curr_va)];
                if (f_pmd_ent == 0) {
                        curr_va += ((unsigned long)1 << 21);
                        continue;
                }

                f_pmd_ent_p = (unsigned long *)f_pmd_ent;
                f_pte_ent = f_pmd_ent_p[pte_index(curr_va)];
                if(f_pte_ent == 0){
                        curr_va += ((unsigned long)1 << 12);
                        continue;
                }

                p = f_pte_ent;
                printf("%lx %lx %d %d %d %d\n", curr_va, get_phys_addr(p), young_bit(p), dirty_bit(p), write_bit(p), user_bit(p) );



                

                // f_pmd_ent = (unsigned long *)f_pud_ent[pud_index(curr_va)];
                // if (*f_pmd_ent == 0){
                //         curr_va += ((unsigned long)1 << 30);
                //         continue;
                // }
                //
                // f_pte_ent = (unsigned long *)f_pmd_ent[pmd_index(curr_va)];
                // // f_pmd_ent = (unsigned long *)(*f_pud_ent + pmd_index(curr_va)
                // //                                 * sizeof(unsigned long));
                // if (*f_pte_ent == 0){
                //         curr_va += ((unsigned long)1 << 21);
                //         continue;
                // }
                //
                //
                // p = *f_pte_ent;
                //
                // printf("%lx %lx %d %d %d %d\n", curr_va, get_phys_addr(p), young_bit(p), dirty_bit(p), write_bit(p), user_bit(p) );

        }

}

int main(int argc, char *argv[])
{
	struct expose_pgtbl_args args;
	pid_t pid;
        unsigned long *base_addr;
        unsigned long va_begin, va_end;
        int res;


        if (argc < 3){
        	printf("input invalid");
        	return -1;
        }


        if (argv[1][0] != '-') {
                pid = strtol(argv[1], NULL, 10);
                va_begin = strtoul(argv[2], NULL, 0);
                va_end = strtoul(argv[3], NULL, 0);
        } else {
		pid = strtol(argv[2], NULL, 10);
                va_begin = strtoul(argv[3], NULL, 0);
                va_end = strtoul(argv[4], NULL, 0);
        }
        printf("the argument is %d %lu %lu \n", pid, va_begin, va_end);

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

        base_addr = mmap(NULL, sizeof(unsigned long) * 512 * 512,
                        PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        if (base_addr == NULL)
                return -1;
        args.fake_pmds = (unsigned long)base_addr;

        base_addr = mmap(NULL, sizeof(unsigned long) * 10 *512 * 512,
                        PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        if (base_addr == NULL)
                return -1;
        args.page_table_addr = (unsigned long)base_addr;

	printf("%d\n", getpid());
        pid = getpid();
	res = syscall(__NR_expose_page_table, pid, &args);
        printf("start printing\n");
	if (res < 0){
		printf("Error: %d\n", res);
                return 0;
        }
        print_pgtbl(&args);

        return 0;
}
