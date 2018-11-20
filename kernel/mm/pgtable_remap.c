#include <linux/pgtable_remap.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <asm/pgtable_types.h>

SYSCALL_DEFINE2(get_pagetable_layout, struct pagetable_layout_info __user *,
        pgtbl_info, int, size)
{
        struct pagetable_layout_info info;

        if (pgtbl_info == NULL)
                return -EINVAL;
        if (size != sizeof(struct pagetable_layout_info))
                return -EINVAL;

        info.pgdir_shift = PGDIR_SHIFT;
        info.pud_shift = PUD_SHIFT;
        info.pmd_shift = PMD_SHIFT;
        info.page_shift = PAGE_SHIFT;

        if (copy_to_user(pgtbl_info, &info, size))
                return -EFAULT;
        return 1;
}

SYSCALL_DEFINE2(expose_page_table, pid_t, pid,
        struct expose_pgtbl_args __user *, args)
{
        if (args == NULL || pid < 0)
                return -EINVAL;
        return 1;
}
