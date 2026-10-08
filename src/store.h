#ifndef BWOPT_STORE_H
#define BWOPT_STORE_H

#include <stdint.h>
#include <time.h>
#include <sqlite3.h>

#include "config.h"
#include "monitor.h"

#define BW_STORE_VERSION 1

/* class name stored for samples with class_idx BW_UNCLASSIFIED */
#define BW_STORE_UNCLASSIFIED "unclassified"

/* Aggregate of the samples of one (iface, class) pair. */
struct bw_store_stat {
    char iface[16];
    char cls[BW_NAME_MAX];
    uint64_t samples;          /* rows considered */
    uint64_t packets, bytes;   /* sums over those rows */
    uint64_t avg_bps;          /* integer mean of bps */
    uint64_t peak_bps;         /* maximum bps */
};

/*
 * Opens or creates the database at path and, inside one transaction,
 * creates the samples and tuning tables and sets user_version to
 * BW_STORE_VERSION. Returns SQLITE_OK on success or an SQLite error code.
 * As with sqlite3_open, *db is set even on failure (unless memory ran
 * out) so sqlite3_errmsg(*db) describes the error; the caller always
 * releases it with bw_store_close.
 */
int bw_store_open(const char *path, sqlite3 **db);

/* Closes a handle from bw_store_open; NULL is ignored. */
void bw_store_close(sqlite3 *db);

/*
 * Inserts n samples for iface in one transaction with a prepared
 * statement. class_idx is mapped to the class name from cfg, or to
 * "unclassified" for BW_UNCLASSIFIED and indexes outside the config.
 * Returns SQLITE_OK, or an error code after rolling the whole batch back
 * (a duplicate (ts, iface, class) gives SQLITE_CONSTRAINT).
 */
int bw_store_put(sqlite3 *db, const char *iface, const struct bw_config *cfg,
                 const struct bw_sample *s, int n);

/* Records one rate change of cls on iface. Returns SQLITE_OK or an error code. */
int bw_store_tuning(sqlite3 *db, time_t ts, const char *iface, const char *cls,
                    uint64_t old_rate, uint64_t new_rate);

/*
 * Reads new_rate of the most recent tuning row for (iface, cls); among
 * rows with the same ts the last inserted wins. Returns 1 and sets *rate
 * when a row exists, 0 when none does, -1 on error.
 */
int bw_store_latest_rate(sqlite3 *db, const char *iface, const char *cls, uint64_t *rate);

/*
 * Aggregates samples per (iface, class), ordered by iface and class name.
 * iface NULL means every interface; only rows with ts >= since count;
 * last_n > 0 keeps only the last_n most recent rows of each pair.
 * Writes at most max results and returns the number of pairs found
 * (which may exceed max), or -1 on error.
 */
int bw_store_query(sqlite3 *db, const char *iface, time_t since, int last_n,
                   struct bw_store_stat *out, int max);

#endif
