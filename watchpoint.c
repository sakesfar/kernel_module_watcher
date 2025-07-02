 #include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/ptrace.h>

static unsigned long watch_address = 0;
module_param(watch_address, ulong, 0644);
MODULE_PARM_DESC(watch_address, "Address to set hardware watchpoint at");

static struct perf_event **watchpoint_event;  
static struct kobject *watch_kobj;

static void watchpoint_handler(struct perf_event *bp,
                               struct perf_sample_data *data,
                               struct pt_regs *regs)
{
    pr_info("[watchpoint] Access detected at 0x%lx\n", watch_address);
    pr_info("[watchpoint] PID: %d (%s), IP: 0x%lx\n", current->pid, current->comm, instruction_pointer(regs));
    dump_stack();
}

static int set_watchpoint(unsigned long addr)
{
    struct perf_event_attr attr = {};

    if (addr % HW_BREAKPOINT_LEN_4 != 0) 
    {
        pr_err("Watch address not 4-byte aligned: 0x%lx\n", addr);
        return -EINVAL;
    }

    if (watchpoint_event) 
    {
        unregister_wide_hw_breakpoint(watchpoint_event);
        watchpoint_event = NULL;
    }

    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(struct perf_event_attr);
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_RW;
    attr.sample_period = 1;
    attr.disabled = 0;

    watchpoint_event = register_wide_hw_breakpoint(&attr, watchpoint_handler, NULL);
    if (IS_ERR(watchpoint_event)) 
    {
        pr_err("Failed to register watchpoint: %ld\n", PTR_ERR(watchpoint_event));
        watchpoint_event = NULL;
        return PTR_ERR(watchpoint_event);
    }

    pr_info("Watchpoint set at address: 0x%lx\n", addr);
    return 0;
}

static ssize_t watch_address_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%lx\n", watch_address);
}

static ssize_t watch_address_store(struct kobject *kobj, struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
    int ret = kstrtoul(buf, 0, &watch_address);
    if (ret)
        return ret;

    ret = set_watchpoint(watch_address);
    return ret ? ret : count;
}

static struct kobj_attribute watch_attr =__ATTR(watch_address, 0644, watch_address_show, watch_address_store);

static int __init watchpoint_init(void)
{
    int ret;

    watch_kobj = kobject_create_and_add("watchpoint", kernel_kobj);
    if (!watch_kobj)
        return -ENOMEM;

    ret = sysfs_create_file(watch_kobj, &watch_attr.attr);
    if (ret) {
        kobject_put(watch_kobj);
        return ret;
    }

      if(watch_address!=0)
      {
        ret = set_watchpoint(watch_address);
        if (ret == 0)
            pr_info("Watchpoint address was provided by the user: 0x%lx\n", watch_address);
        else
            pr_err("Failed to set watchpoint from the user: %d\n", ret);
      }

    pr_info("Kernel watchpoint module loaded successfully.\n");
    return 0;
}

static void __exit watchpoint_exit(void)
{
    if (watchpoint_event) 
    {
        unregister_wide_hw_breakpoint(watchpoint_event);
        watchpoint_event = NULL;
    }

    if (watch_kobj) 
    {
        sysfs_remove_file(watch_kobj, &watch_attr.attr);
        kobject_put(watch_kobj);
    }  

    pr_info("Watchpoint module unloaded.\n");
}

module_init(watchpoint_init);
module_exit(watchpoint_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arsen Z.");
MODULE_DESCRIPTION("Hardware watchpoint kernel module using perf_event API");
