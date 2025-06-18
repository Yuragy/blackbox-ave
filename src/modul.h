#ifndef MODUL_H
#define MODUL_H

#include <linux/types.h>

typedef int (*mod_init_func)(void);
typedef void (*mod_exit_func)(void);
typedef int (*mod_cmd_func)(const char __user *buf, size_t count);

struct module_interface {
    const char *name;
    mod_init_func init;
    mod_exit_func exit;
    mod_cmd_func command;
    void *data;
};

#endif /* MODUL_H */
