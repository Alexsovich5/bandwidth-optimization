#include "autotune.h"

#define STEP 1000ULL   /* every rate is a multiple of 1000 bit/s */

static uint64_t round_down(uint64_t v)
{
    return v - v % STEP;
}

static uint64_t round_up(uint64_t v)
{
    return v % STEP ? v - v % STEP + STEP : v;
}

static uint64_t absdiff(uint64_t a, uint64_t b)
{
    return a > b ? a - b : b - a;
}

enum role { NEUTRAL, DONOR, RECEIVER };

/*
 * Utilisation is measured against the configured rate:
 * U = 100 * A / C, compared without dividing.
 */
static enum role classify(const struct bw_autotune_cfg *t, uint64_t avg, uint64_t conf)
{
    if (conf == 0)
        return NEUTRAL;
    if (avg * 100 < (uint64_t)t->low_watermark * conf)
        return DONOR;
    if (avg * 100 >= (uint64_t)t->high_watermark * conf)
        return RECEIVER;
    return NEUTRAL;
}

/*
 * Lowers the increased targets until the sum fits within total, taking
 * from each class in proportion to its increase and never below its
 * current rate.
 */
static void clamp_to_total(int n, uint64_t total, const uint64_t *cur, uint64_t *target)
{
    uint64_t sum = 0, increase = 0, excess;
    int i;

    for (i = 0; i < n; i++) {
        sum += target[i];
        if (target[i] > cur[i])
            increase += target[i] - cur[i];
    }
    if (sum <= total || increase == 0)
        return;
    excess = sum - total;

    for (i = 0; i < n; i++) {
        long double share;
        uint64_t inc, cut;

        if (target[i] <= cur[i])
            continue;
        inc = target[i] - cur[i];
        share = (long double)excess * (long double)inc / (long double)increase;
        cut = round_up((uint64_t)share + 1);
        if (cut >= inc) {
            sum -= inc;
            target[i] = cur[i];
        } else {
            sum -= cut;
            target[i] -= cut;
        }
    }

    /* rounding leftovers: give back whole increases until the sum fits */
    for (i = 0; i < n && sum > total; i++) {
        if (target[i] > cur[i]) {
            sum -= target[i] - cur[i];
            target[i] = cur[i];
        }
    }
}

int bw_autotune(const struct bw_config *cfg, const uint64_t *avg_bps,
                const uint64_t *cur_rate, uint64_t *new_rate)
{
    const struct bw_autotune_cfg *t = &cfg->tune;
    uint64_t conf[BW_MAX_CLASSES], floor_bps[BW_MAX_CLASSES], hyst[BW_MAX_CLASSES];
    enum role role[BW_MAX_CLASSES];
    int n = cfg->nclasses, i, ndonors = 0, nreceivers = 0, changed = 0;

    if (n > BW_MAX_CLASSES)
        n = BW_MAX_CLASSES;

    for (i = 0; i < n; i++) {
        conf[i] = round_down(cfg->classes[i].rate_bps);
        floor_bps[i] = round_up(cfg->classes[i].rate_bps * t->min_share / 100);
        if (floor_bps[i] > conf[i])
            floor_bps[i] = conf[i];
        hyst[i] = conf[i] * t->hysteresis / 100;
        role[i] = classify(t, avg_bps[i], conf[i]);
        if (role[i] == DONOR)
            ndonors++;
        else if (role[i] == RECEIVER)
            nreceivers++;
    }

    if (ndonors > 0 && nreceivers > 0) {
        uint64_t pool = 0, receiver_pct = 0;

        for (i = 0; i < n; i++) {
            if (role[i] == DONOR) {
                uint64_t want = avg_bps[i] * 12 / 10;

                if (want < floor_bps[i])
                    want = floor_bps[i];
                if (want > conf[i])
                    want = conf[i];
                new_rate[i] = round_down(want);
                if (new_rate[i] < floor_bps[i])
                    new_rate[i] = floor_bps[i];
                pool += conf[i] - new_rate[i];
            } else if (role[i] == RECEIVER) {
                receiver_pct += cfg->classes[i].pct;
            }
        }
        for (i = 0; i < n; i++) {
            if (role[i] == RECEIVER) {
                uint64_t extra = receiver_pct
                    ? pool * cfg->classes[i].pct / receiver_pct
                    : pool / (uint64_t)nreceivers;

                new_rate[i] = round_down(conf[i] + extra);
            } else if (role[i] == NEUTRAL) {
                new_rate[i] = conf[i];
            }
        }
    } else {
        /* drift back half-way to the configured rate, snapping when close */
        for (i = 0; i < n; i++) {
            uint64_t r = cur_rate[i], target;

            if (r >= conf[i])
                target = r - (r - conf[i]) / 2;
            else
                target = r + (conf[i] - r) / 2;
            target = round_down(target);
            if (r < conf[i] && target < r)
                target = r;   /* rounding must not move a rate away from conf */
            if (absdiff(conf[i], target) <= hyst[i])
                target = conf[i];
            new_rate[i] = target;
        }
    }

    for (i = 0; i < n; i++)
        if (absdiff(new_rate[i], cur_rate[i]) < hyst[i])
            new_rate[i] = cur_rate[i];

    clamp_to_total(n, cfg->total_bps, cur_rate, new_rate);

    for (i = 0; i < n; i++)
        if (new_rate[i] != cur_rate[i])
            changed++;
    return changed;
}
