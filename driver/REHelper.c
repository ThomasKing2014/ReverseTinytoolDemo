/*
** Author: ThomasKing
** Date: 2015/02/23
*/ 
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#define RE_DEV "REHelper"
#define CMD_BASE 0xC0000000
#define DUMP_MEM (CMD_BASE + 1)
#define SET_PID  (CMD_BASE + 2)
#define MODIFY_M (CMD_BASE + 3)

static int (*access_remote_vm)(struct mm_struct *, unsigned long, void *, int, int);

struct dump_request{
    pid_t pid;
    unsigned long addr;
    ssize_t count;
    char __user *buf;
};

pid_t monitor_pid = -1;

asmlinkage int jsys_open(const char *pathname, int flags, mode_t mode){
    pid_t current_pid = current_thread_info()->task->tgid;    

    if(!monitor_pid || (current_pid == monitor_pid)){
        printk(KERN_INFO "[open] pathname %s, flags: %x, mode: %x\n", 
            pathname, flags, mode);
    }
    
    jprobe_return();
    return 0;
}

asmlinkage int jsys_openat(int dirfd, const char *pathname, int flags, mode_t mode){
    pid_t current_pid = current_thread_info()->task->tgid;    

    if(!monitor_pid || (current_pid == monitor_pid)){
        printk(KERN_INFO "[openat] dirfd: %d, pathname %s, flags: %x, mode: %x\n", 
            dirfd, pathname, flags, mode);
    }
    
    jprobe_return();
    return 0;
}

asmlinkage long jsys_ptrace(long request, long pid, unsigned long addr,
               unsigned long data){
    pid_t current_pid = current_thread_info()->task->tgid;    

    if(!monitor_pid || (current_pid == monitor_pid)){
        switch(request){
            case PTRACE_TRACEME: {
                printk(KERN_INFO "PTRACE_TRACEME: [src]pid = %d\n", current_pid);            
            }break;
            case PTRACE_PEEKDATA: {
                printk(KERN_INFO "PTRACE_PEEKDATA: [src]pid = %d --> [dst]pid = %d, addr: %lx, data: %lx\n", 
                    current_pid, pid, addr, data);            
            }break;

            default:{

            }break;
        }
    }
    
    jprobe_return();
    return 0;
}

asmlinkage int jinotify_add_watch(int fd, const char *pathname, uint32_t mask){
    pid_t current_pid = current_thread_info()->task->tgid;    

    if(!monitor_pid || (current_pid == monitor_pid)){
        printk(KERN_INFO "[inotify_add_watch]: fd: %d, pathname: %s, mask: %x", 
            fd, pathname, mask);
    }

    jprobe_return();
    return 0;    
}

static struct jprobe ptrace_probe = {
    .entry          = jsys_ptrace,
    .kp = {
        .symbol_name    = "sys_ptrace",
    },
};

static struct jprobe open_probe = {
    .entry          = jsys_open,
    .kp = {
        .symbol_name    = "sys_open",
    },
};

static struct jprobe openat_probe = {
    .entry          = jsys_openat,
    .kp = {
        .symbol_name    = "sys_openat",
    },
};

static struct jprobe inotify_add_watch_probe = {
    .entry          = jinotify_add_watch,
    .kp = {
        .symbol_name    = "sys_inotify_add_watch",
    },
};

static struct jprobe *my_jprobe[] = {
    &open_probe,
    &openat_probe,
    &ptrace_probe,
    &inotify_add_watch_probe
};

static ssize_t mem_rw(struct mm_struct *mm, char __user *buf,
            size_t count, unsigned long addr, int write)
{
    ssize_t copied;
    char *page;

    if (!mm)
        return 0;

    page = (char *)__get_free_page(GFP_TEMPORARY);
    if (!page)
        return -ENOMEM;

    copied = 0;
    if (!atomic_inc_not_zero(&mm->mm_users))
        goto free;

    while (count > 0) {
        int this_len = min_t(int, count, PAGE_SIZE);

        if (write && copy_from_user(page, buf, this_len)) {
            copied = -EFAULT;
            break;
        }

        this_len = access_remote_vm(mm, addr, page, this_len, write);
        if (!this_len) {
            if (!copied)
                copied = -EIO;
            break;
        }

        if (!write && copy_to_user(buf, page, this_len)) {
            copied = -EFAULT;
            break;
        }

        buf += this_len;
        addr += this_len;
        copied += this_len;
        count -= this_len;
    }

    mmput(mm);
free:
    free_page((unsigned long) page);
    return copied;
}

static ssize_t mem_read(struct mm_struct *mm, char __user *buf,
            size_t count, unsigned long addr)
{
    return mem_rw(mm, buf, count, addr, 0);
}

static ssize_t mem_write(struct mm_struct *mm, char __user *buf,
            size_t count, unsigned long addr)
{
    return mem_rw(mm, (char __user*)buf, count, addr, 1);
}

static int REHelper_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "REHelper device open success!\n");
    return 0;
}

static long REHelper_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
	long ret = 0;
    void __user *argp = (void __user *)arg;
    struct task_struct *target_task;
    struct dump_request *request = (struct dump_request *)argp;
    
	switch(cmd){
        case DUMP_MEM:
            target_task = find_task_by_vpid(request->pid);
            if(!target_task){
                printk(KERN_INFO "find_task_by_vpid(%d) failed\n", request->pid);
                ret = -ESRCH;
                return ret;
            }
            request->count = mem_read(target_task->mm, request->buf, request->count, request->addr);
            break;
        case SET_PID:
            monitor_pid = (pid_t) arg;
            printk(KERN_INFO "Set monitor pid: %d\n", monitor_pid);
            break;
        case MODIFY_M:

            break;
        default:
            ret = -EFAULT;
	}
	return ret;
}

static struct file_operations REHelper_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = REHelper_unlocked_ioctl,
    .open = REHelper_open
};

static int major = 0;

struct cdev REHelper_cdev;
 
static struct class *REHelper_cls;

static int REHelper_init(void){
    dev_t dev_id;
    int ret = 0;

    if(major){
        dev_id = MKDEV(major, 0);
        register_chrdev_region(dev_id, 1, RE_DEV);
    } else {
        alloc_chrdev_region(&dev_id, 0, 1, RE_DEV);
        major = MAJOR(dev_id);
    }
    cdev_init(&REHelper_cdev, &REHelper_fops); 
    cdev_add(&REHelper_cdev, dev_id, 1);
    REHelper_cls = class_create(THIS_MODULE, RE_DEV);
    device_create(REHelper_cls, NULL, dev_id, NULL, RE_DEV);

    access_remote_vm = (int (*)(struct mm_struct *, unsigned long, void *, int, int))kallsyms_lookup_name("access_remote_vm");
    if(!access_remote_vm){
        printk(KERN_INFO "Cannot find access_remote_vm [%p]", access_remote_vm);
        return -1;
    }
    printk(KERN_INFO "Find access_remote_vm [%p]", access_remote_vm);

    ret = register_jprobes(&my_jprobe, sizeof(my_jprobe) / sizeof(my_jprobe[0]));
    if (ret < 0) {
        printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
        return -1;
    }
    
    return 0;
}

static void REHelper_exit(void){
    device_destroy(REHelper_cls, MKDEV(major, 0));
    class_destroy(REHelper_cls);
    cdev_del(&REHelper_cdev);
    unregister_chrdev_region(MKDEV(major, 0), 1);

    unregister_jprobes(&my_jprobe, sizeof(my_jprobe) / sizeof(my_jprobe[0]));
}
 
module_init(REHelper_init);
module_exit(REHelper_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ThomasKing");