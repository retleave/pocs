#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/ktime.h>
#include <linux/sched.h>

#define DEV_NAME "session"

#define IOCTL_NEW_SESSION     0xdead0001
#define IOCTL_DELETE_SESSION  0xdead0002

struct session {
    u64 session_id;
    u64 owner_pid;
    char data[0x20];
};

static struct session *sess;

static long session_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {

    switch (cmd) {

        case IOCTL_NEW_SESSION:
            if (sess) {
                pr_info("[SESSION] session already exists\n");
                return -EINVAL;
            }
            sess = kzalloc(sizeof(*sess), GFP_KERNEL_ACCOUNT);
            if (!sess) return -ENOMEM;
            sess->session_id = ktime_get_ns();
            sess->owner_pid  = (u64)task_pid_nr(current);
            pr_info("[SESSION] new session allocated\n");
            break;

        case IOCTL_DELETE_SESSION:
            if (!sess) return -EINVAL;
            pr_info("[SESSION] deleting session\n");
            kfree(sess);
            break;

        default:
            return -EINVAL;
    }

    return 0;
}

static ssize_t session_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {

    char tmp[0x20];
    if (!sess) return -EINVAL;
    if (copy_from_user(tmp, buf, sizeof(tmp))) return -EFAULT;
    memcpy(sess->data, tmp, sizeof(tmp));

    return sizeof(tmp);
}

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = session_ioctl,
    .write          = session_write,
};

static struct miscdevice dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEV_NAME,
    .fops  = &fops,
};

static int __init session_init(void)
{
    sess = NULL;
    pr_info("[SESSION] module loaded\n");
    return misc_register(&dev);
}

static void __exit session_exit(void)
{
    if (sess)
        kfree(sess);

    misc_deregister(&dev);
    pr_info("[SESSION] module unloaded\n");
}

module_init(session_init);
module_exit(session_exit);

MODULE_LICENSE("GPL");
