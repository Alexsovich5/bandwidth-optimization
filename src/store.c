#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "store.h"

static const char schema_sql[] =
    "BEGIN;"
    "CREATE TABLE IF NOT EXISTS samples ("
    "  ts      INTEGER NOT NULL,"
    "  iface   TEXT    NOT NULL,"
    "  class   TEXT    NOT NULL,"
    "  packets INTEGER NOT NULL,"
    "  bytes   INTEGER NOT NULL,"
    "  bps     INTEGER NOT NULL,"
    "  PRIMARY KEY (ts, iface, class)"
    ");"
    "CREATE TABLE IF NOT EXISTS tuning ("
    "  ts INTEGER NOT NULL, iface TEXT NOT NULL, class TEXT NOT NULL,"
    "  old_rate INTEGER NOT NULL, new_rate INTEGER NOT NULL"
    ");"
    "PRAGMA user_version = 1;"
    "COMMIT;";

int bw_store_open(const char *path, sqlite3 **db)
{
    int rc;

    *db = NULL;
    rc = sqlite3_open_v2(path, db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK)
        return rc;
    sqlite3_busy_timeout(*db, 5000);
    /* On failure the open transaction is rolled back when the handle is
     * closed; leaving it until then keeps the message in sqlite3_errmsg. */
    return sqlite3_exec(*db, schema_sql, NULL, NULL, NULL);
}

void bw_store_close(sqlite3 *db)
{
    if (db)
        sqlite3_close(db);
}

static const char *class_name(const struct bw_config *cfg, int idx)
{
    if (idx >= 0 && idx < cfg->nclasses)
        return cfg->classes[idx].name;
    return BW_STORE_UNCLASSIFIED;
}

int bw_store_put(sqlite3 *db, const char *iface, const struct bw_config *cfg,
                 const struct bw_sample *s, int n)
{
    static const char sql[] =
        "INSERT INTO samples (ts, iface, class, packets, bytes, bps)"
        " VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
    sqlite3_stmt *st = NULL;
    int rc, i;

    rc = sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
    if (rc != SQLITE_OK)
        return rc;
    rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
    for (i = 0; rc == SQLITE_OK && i < n; i++) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)s[i].ts);
        sqlite3_bind_text(st, 2, iface, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 3, class_name(cfg, s[i].class_idx), -1, SQLITE_STATIC);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)s[i].packets);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)s[i].bytes);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)s[i].bps);
        rc = sqlite3_step(st);
        if (rc == SQLITE_DONE)
            rc = SQLITE_OK;
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    if (rc == SQLITE_OK)
        rc = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    if (rc != SQLITE_OK)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    return rc;
}

int bw_store_tuning(sqlite3 *db, time_t ts, const char *iface, const char *cls,
                    uint64_t old_rate, uint64_t new_rate)
{
    static const char sql[] =
        "INSERT INTO tuning (ts, iface, class, old_rate, new_rate)"
        " VALUES (?1, ?2, ?3, ?4, ?5)";
    sqlite3_stmt *st;
    int rc;

    rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
    if (rc != SQLITE_OK)
        return rc;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)ts);
    sqlite3_bind_text(st, 2, iface, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, cls, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)old_rate);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)new_rate);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? SQLITE_OK : rc;
}

int bw_store_latest_rate(sqlite3 *db, const char *iface, const char *cls, uint64_t *rate)
{
    static const char sql[] =
        "SELECT new_rate FROM tuning WHERE iface = ?1 AND class = ?2"
        " ORDER BY ts DESC, rowid DESC LIMIT 1";
    sqlite3_stmt *st;
    int rc, ret;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, iface, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, cls, -1, SQLITE_STATIC);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *rate = (uint64_t)sqlite3_column_int64(st, 0);
        ret = 1;
    } else {
        ret = rc == SQLITE_DONE ? 0 : -1;
    }
    sqlite3_finalize(st);
    return ret;
}

static void copy_text(char *dst, size_t len, const unsigned char *src)
{
    snprintf(dst, len, "%s", src ? (const char *)src : "");
}

/*
 * Prepares the aggregate query of bw_store_query; NULL on error. The
 * caller steps it and reads each row with read_stat.
 */
static sqlite3_stmt *prepare_query(sqlite3 *db, const char *iface, time_t since, int last_n)
{
    /* integer division keeps the mean exact and rounded down */
    static const char sql[] =
        "SELECT iface, class, COUNT(*), SUM(packets), SUM(bytes),"
        "       SUM(bps) / COUNT(*), MAX(bps)"
        " FROM samples s"
        " WHERE (?1 IS NULL OR iface = ?1) AND ts >= ?2"
        "   AND (?3 <= 0 OR ts IN ("
        "        SELECT ts FROM samples r"
        "        WHERE r.iface = s.iface AND r.class = s.class AND r.ts >= ?2"
        "        ORDER BY r.ts DESC LIMIT ?3))"
        " GROUP BY iface, class"
        " ORDER BY iface, class";
    sqlite3_stmt *st;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return NULL;
    if (iface)
        sqlite3_bind_text(st, 1, iface, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 1);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)since);
    sqlite3_bind_int(st, 3, last_n);
    return st;
}

static void read_stat(sqlite3_stmt *st, struct bw_store_stat *o)
{
    copy_text(o->iface, sizeof o->iface, sqlite3_column_text(st, 0));
    copy_text(o->cls, sizeof o->cls, sqlite3_column_text(st, 1));
    o->samples = (uint64_t)sqlite3_column_int64(st, 2);
    o->packets = (uint64_t)sqlite3_column_int64(st, 3);
    o->bytes = (uint64_t)sqlite3_column_int64(st, 4);
    o->avg_bps = (uint64_t)sqlite3_column_int64(st, 5);
    o->peak_bps = (uint64_t)sqlite3_column_int64(st, 6);
}

int bw_store_query(sqlite3 *db, const char *iface, time_t since, int last_n,
                   struct bw_store_stat *out, int max)
{
    sqlite3_stmt *st = prepare_query(db, iface, since, last_n);
    int rc, n = 0;

    if (st == NULL)
        return -1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n < max)
            read_stat(st, &out[n]);
        n++;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? n : -1;
}

#define QUERY_ALL_FIRST 16

int bw_store_query_all(sqlite3 *db, const char *iface, time_t since, int last_n,
                       struct bw_store_stat **out)
{
    sqlite3_stmt *st = prepare_query(db, iface, since, last_n);
    struct bw_store_stat *rows = NULL;
    int rc, n = 0, cap = 0;

    *out = NULL;
    if (st == NULL)
        return -1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n == cap) {
            int ncap = cap == 0 ? QUERY_ALL_FIRST : cap * 2;
            struct bw_store_stat *nr;

            if (ncap <= cap || (size_t)ncap > SIZE_MAX / sizeof *rows
                || (nr = realloc(rows, (size_t)ncap * sizeof *rows)) == NULL) {
                rc = SQLITE_NOMEM;
                break;
            }
            rows = nr;
            cap = ncap;
        }
        read_stat(st, &rows[n++]);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        free(rows);
        return -1;
    }
    *out = rows;
    return n;
}
