#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#define __NR_get_pagetable_layout 326
#define __NR_expose_page_table 327

struct pagetable_layout_info {
        uint32_t pgdir_shift;
        uint32_t pud_shift;
        uint32_t pmd_shift;
        uint32_t page_shift;
 };

int main(int argc, char **argv)
{
	struct pagetable_layout_info info;

	int res = syscall(__NR_get_pagetable_layout, &info,
			sizeof(struct pagetable_layout_info));
        if (res)
                printf("layout: pgd[%d] pud[%d] pmd[%d] pg_shift[%d]\n",
                        info.pgdir_shift, info.pud_shift,
                        info.pmd_shift, info.page_shift);
        
        return 0;
}
