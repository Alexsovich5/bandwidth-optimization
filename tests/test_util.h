#ifndef BWOPT_TEST_UTIL_H
#define BWOPT_TEST_UTIL_H

#include <inttypes.h>
#include <check.h>

/* Check 0.9.8 has no 64-bit assert; ck_assert_int_* formats with %d. */
#define ASSERT_U64_EQ(a, b) \
    ck_assert_msg((uint64_t)(a) == (uint64_t)(b), \
                  "%" PRIu64 " != %" PRIu64, (uint64_t)(a), (uint64_t)(b))

#endif
