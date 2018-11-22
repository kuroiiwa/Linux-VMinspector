#include <linux/pgtable_remap.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <asm/pgtable_types.h>
#include <linux/rcupdate.h>
#include <asm/pgtable.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

#define PER_PUDTBL_SIZE (sizeof(unsigned long) * PTRS_PER_PUD)
#define PER_PMDTBL_SIZE (sizeof(unsigned long) * PTRS_PER_PMD)
#define PER_PTETBL_SZIE (sizeof(unsigned long) * PTRS_PER_PTE)
static int f_pgd_n = 0;
static int f_pud_n = 0;
static int f_pmd_n = 0;
static int pgd_index_pre = -1;
static int pud_index_pre = -1;
static int pmd_index_pre = -1;

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

int save_pgd(unsigned long fake_pgd, unsigned long fake_puds)
{
        unsigned long *f_pgd_p;
        unsigned long f_pud_addr;

        f_pgd_p = (unsigned long *)(fake_pgd + f_pgd_n
                        * sizeof(unsigned long));
        f_pgd_n++;

        f_pud_addr = fake_puds + f_pud_n * PER_PUDTBL_SIZE;

        f_pud_n++;

        printk("save_pgd:%d-%d-%d\n", f_pgd_n, f_pud_n, f_pmd_n);

        if (copy_to_user(f_pgd_p, &f_pud_addr, sizeof(unsigned long)))
                return -EFAULT;
        return 0;
}
int save_pud(unsigned long fake_puds, unsigned long fake_pmds)
{
        unsigned long *f_pud_p;
        unsigned long f_pmd_addr, f_pud_tbl_addr;

        f_pud_tbl_addr = fake_puds + f_pgd_n * PER_PUDTBL_SIZE;

        f_pud_p = (unsigned long *) (f_pud_tbl_addr +
                                f_pud_n * sizeof(unsigned long));

        f_pmd_addr = fake_pmds + ((f_pgd_n - 1) * PTRS_PER_PUD
                        + f_pud_n) * PER_PMDTBL_SIZE;

        printk("save_pud:%d-%d-%d\n", f_pgd_n, f_pud_n, f_pmd_n);

        if (copy_to_user(f_pud_p, &f_pmd_addr, sizeof(unsigned long)))
                return -EFAULT;
        return 0;

}

SYSCALL_DEFINE2(expose_page_table, pid_t, pid,
        struct expose_pgtbl_args __user *, args)
{
        struct expose_pgtbl_args args_k;
        struct task_struct *p;
        struct mm_struct *mm;
        struct vm_area_struct *vma;
        const unsigned long ubound_va = 0x7fffffffffff;
        //unsigned long *pgd_k;
        unsigned long start, end, curr_va;
        int last_vm, res;
        pgd_t *pgd_p;
        pud_t *pud_p;

        if (args == NULL || pid < 0)
                return -EINVAL;
        if (copy_from_user(&args_k, args,
                        sizeof(struct expose_pgtbl_args)))
                return -EFAULT;

        if (args_k.begin_vaddr > args_k.end_vaddr)
                return -EINVAL;
        if (args_k.end_vaddr > ubound_va)
                args_k.end_vaddr = ubound_va;
        /*Todo: Create pgd pud pmd in kernel.
         *Create mapping memory space using mmap()
         *Find PTE for each va of target process and remap it
         *      using remap_pfn_range()
         */


         /*
          * get task_struct from pid
          */
        rcu_read_lock();
        if (pid == -1)
                p = current;
        else
                p = find_task_by_vpid(pid);
        rcu_read_unlock();
        if(!p)
                return -ESRCH;

        mm = get_task_mm(p);

        if (mm == NULL)
                return -EFAULT;

        // size_pgd = PTRS_PER_PGD;
        // size_pud = (pgd_index(args_k.end_vaddr) - pgd_index(args_k.begin_vaddr)
        //         + 1) * PTRS_PER_PUD;
        // size_pmd = size_pud * PTRS_PER_PMD;
        // printk("%lu, %lu, %lu\n", size_pgd, size_pud, size_pmd);
        //pgd_k = kmalloc(size_pgd * sizeof(unsigned long), GFP_KERNEL);

        vma = find_vma(mm, args_k.begin_vaddr);

        if (vma == NULL)
                return -EFAULT;

        last_vm = 0;
        spin_lock(&mm->page_table_lock);
        for (; vma->vm_next != NULL; vma = vma->vm_next) {
                if (likely(vma->vm_start > args_k.begin_vaddr))
                        start = vma->vm_start;
                else
                        start = args_k.begin_vaddr;

                if (likely(vma->vm_end < args_k.end_vaddr))
                        end = vma->vm_end;
                else {
                        end = args_k.end_vaddr;
                        last_vm = 1;
                }

                for (curr_va = start; curr_va <= end; curr_va++) {
                        /* PGD */
                        pgd_p = pgd_offset(mm, curr_va);
                        if (pgd_none(*pgd_p))
                                continue;
                        if (pgd_index(curr_va) != pgd_index_pre) {
                                f_pud_n = 0;
                                f_pmd_n = 0;
                                res = save_pgd(args_k.fake_pgd, args_k.fake_puds);
                                if (unlikely(res < 0))
                                        return res;
                        }

                        /* PUD */
                        pud_p = pud_offset(pgd_p, curr_va);
                        if (pud_none(*pud_p))
                                continue;
                        if (pud_index(curr_va) != pud_index_pre){
                                f_pmd_n = 0;
                                res = save_pud(args_k.fake_puds,
                                                        args_k.fake_pmds);
                                if (unlikely(res < 0))
                                        return res;
                        }
                        // /* PMD */
                        // pmd_t *pmd_p = pmd_offset(pud_p, curr_va);
                        // if (pmd_none(*pmd_p))
                        //         continue;
                        // interpret_pmd(curr_va, args_k.fake_pmds,
                        //                         args_k.page_table_addr);
                        // if (res < 0)
                        //         return res;
                }
                if (unlikely(last_vm))
                        break;
        }
        spin_unlock(&mm->page_table_lock);
        return 1;
}
