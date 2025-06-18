#ifndef KERNEL_H
#define KERNEL_H

#include "modul.h"

int register_submodule(struct module_interface *mod);
int unregister_submodule(const char *name);
int ave_handle_command(const char *cmd, size_t len);

#endif /* KERNEL_H */
