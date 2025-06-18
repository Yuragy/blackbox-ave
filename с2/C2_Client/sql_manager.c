#include "sql_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sqlite3 *db = NULL;

int sql_manager_init(const char *db_path) {
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return rc;
    }
    const char *sql = "CREATE TABLE IF NOT EXISTS events ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, "
                      "event TEXT NOT NULL);";
    char *errmsg = NULL;
    rc = sqlite3_exec(db, sql, 0, 0, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (table creation): %s\n", errmsg);
        sqlite3_free(errmsg);
        return rc;
    }
    return SQLITE_OK;
}

int sql_manager_log_event(const char *event) {
    if (!db) return SQLITE_ERROR;
    const char *sql = "INSERT INTO events (event) VALUES (?);";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    sqlite3_bind_text(stmt, 1, event, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert event: %s\n", sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

void sql_manager_close(void) {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
}
