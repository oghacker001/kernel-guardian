
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/err.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nishant");
MODULE_DESCRIPTION(
    "KERNEL GUARDIAN - Linux Kernel Security Monitoring Platform"
);
MODULE_VERSION("1.4");

static struct kretprobe guardian_rp;

/*
 * Entry handler
 */
static int guardian_entry_handler(
    struct kretprobe_instance *ri,
    struct pt_regs *regs)
{
    return 0;
}

/*
 * Return handler
 *
 * copy_process() returns a task_struct pointer on success.
 *
 * On x86-64 kernel pointers may have the high bit set, so
 * checking "ret > 0" is incorrect because a valid kernel
 * pointer can appear negative when stored in signed long.
 */
static int guardian_ret_handler(
    struct kretprobe_instance *ri,
    struct pt_regs *regs)
{
    unsigned long raw_ret;
    struct task_struct *child;

    raw_ret = (unsigned long)regs_return_value(regs);

    /*
     * copy_process() returns ERR_PTR() on failure.
     */
    if (IS_ERR_VALUE(raw_ret))
        return 0;

    if (raw_ret == 0)
        return 0;

    child = (struct task_struct *)raw_ret;

    /*
     * Basic sanity check before accessing task_struct.
     */
    if (!child)
        return 0;

    pr_info(
        "KERNEL GUARDIAN: PROCESS CREATED | "
        "parent=%s[%d] child=%s[%d]\n",
        current->comm,
        current->pid,
        child->comm,
        child->pid
    );

    return 0;
}

/*
 * Module initialization
 */
static int __init guardian_init(void)
{
    int ret;

    pr_info(
        "KERNEL GUARDIAN: module loaded successfully\n"
    );

    pr_info(
        "KERNEL GUARDIAN: registering copy_process kretprobe\n"
    );

    memset(&guardian_rp, 0, sizeof(guardian_rp));

    guardian_rp.kp.symbol_name = "copy_process";
    guardian_rp.entry_handler = guardian_entry_handler;
    guardian_rp.handler = guardian_ret_handler;
    guardian_rp.maxactive = 64;

    ret = register_kretprobe(&guardian_rp);

    if (ret < 0) {
        pr_err(
            "KERNEL GUARDIAN: failed to register kretprobe: %d\n",
            ret
        );

        return ret;
    }

    pr_info(
        "KERNEL GUARDIAN: copy_process kretprobe "
        "registered successfully\n"
    );

    return 0;
}

/*
 * Module cleanup
 */
static void __exit guardian_exit(void)
{
    unregister_kretprobe(&guardian_rp);

    pr_info(
        "KERNEL GUARDIAN: copy_process kretprobe unregistered\n"
    );

    pr_info(
        "KERNEL GUARDIAN: module unloaded successfully\n"
    );
}

module_init(guardian_init);
module_exit(guardian_exit);

