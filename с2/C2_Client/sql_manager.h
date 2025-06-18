#ifndef SQL_MANAGER_H
#define SQL_MANAGER_H

#include <sqlite3.h>

int sql_manager_init(const char *db_path);
int sql_manager_log_event(const char *event);
void sql_manager_close(void);

#endif /* SQL_MANAGER_H */
