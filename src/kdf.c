#include "internal.h"

#include <math.h>
#include <string.h>

_Static_assert(KSEC_ARGON_OPS_PRODUCTION >= KSEC_ARGON_OPS_MIN
        && KSEC_ARGON_OPS_PRODUCTION <= KSEC_ARGON_OPS_MAX,
        "production Argon2id ops is outside the approved envelope");
_Static_assert(KSEC_ARGON_MEM_PRODUCTION >= KSEC_ARGON_MEM_MIN
        && KSEC_ARGON_MEM_PRODUCTION <= KSEC_ARGON_MEM_MAX,
        "production Argon2id memory is outside the approved envelope");

/* One hundred milliseconds of headroom keeps a noisy maximum off the 2000 ms
 * ceiling. The monotonic check is the median at a fixed memory size, which is
 * what the harness records. */

static const uint32_t OPS_GRID[KSEC_ARGON_OPS_COUNT] = {3U, 4U, 5U, 6U};
static const uint32_t MEM_GRID_MIB[KSEC_ARGON_MEM_COUNT] = {256U, 384U, 512U};

static bool grid_index(const uint32_t *grid, size_t count, uint32_t value,
                       size_t *index_out) {
    size_t index;
    for (index = 0U; index < count; index++) {
        if (grid[index] == value) {
            *index_out = index;
            return true;
        }
    }
    return false;
}

static int observation_ordered(const ksec_argon_observation *row) {
    return isfinite(row->min_ms) && isfinite(row->median_ms)
        && isfinite(row->p95_ms) && isfinite(row->max_ms)
        && row->min_ms >= 0.0
        && row->median_ms >= row->min_ms
        && row->p95_ms >= row->median_ms
        && row->max_ms >= row->p95_ms;
}

ksec_result ksec_argon_select_point(const ksec_argon_observation *rows, size_t count,
                                    uint32_t *ops_out, uint32_t *mem_mib_out) {
    ksec_argon_observation grid[KSEC_ARGON_MEM_COUNT][KSEC_ARGON_OPS_COUNT];
    bool seen[KSEC_ARGON_MEM_COUNT][KSEC_ARGON_OPS_COUNT];
    bool found = false;
    uint64_t best_cost = 0U;
    uint32_t best_ops = 0U;
    uint32_t best_mem = 0U;
    size_t index;
    size_t mem_index;
    size_t ops_index;
    if (rows == NULL || ops_out == NULL || mem_mib_out == NULL
            || count != KSEC_ARGON_GRID_COUNT) {
        return KSEC_ERR_INVALID;
    }
    memset(seen, 0, sizeof seen);
    for (index = 0U; index < count; index++) {
        size_t ops_at = 0U;
        size_t mem_at = 0U;
        if (!grid_index(OPS_GRID, KSEC_ARGON_OPS_COUNT, rows[index].ops, &ops_at)
                || !grid_index(MEM_GRID_MIB, KSEC_ARGON_MEM_COUNT, rows[index].mem_mib, &mem_at)
                || seen[mem_at][ops_at]
                || !observation_ordered(&rows[index])) {
            return KSEC_ERR_INVALID;
        }
        seen[mem_at][ops_at] = true;
        grid[mem_at][ops_at] = rows[index];
    }
    for (mem_index = 0U; mem_index < KSEC_ARGON_MEM_COUNT; mem_index++) {
        for (ops_index = 1U; ops_index < KSEC_ARGON_OPS_COUNT; ops_index++) {
            if (grid[mem_index][ops_index].median_ms
                    < grid[mem_index][ops_index - 1U].median_ms) {
                return KSEC_ERR_INVALID;
            }
        }
    }
    for (mem_index = 0U; mem_index < KSEC_ARGON_MEM_COUNT; mem_index++) {
        for (ops_index = 0U; ops_index < KSEC_ARGON_OPS_COUNT; ops_index++) {
            const ksec_argon_observation *row = &grid[mem_index][ops_index];
            uint64_t cost;
            if (row->max_ms + KSEC_ARGON_MIN_HEADROOM_MS > KSEC_ARGON_CEILING_MS) continue;
            cost = (uint64_t)row->ops * (uint64_t)row->mem_mib;
            if (!found || cost > best_cost
                    || (cost == best_cost && row->mem_mib > best_mem)) {
                found = true;
                best_cost = cost;
                best_ops = row->ops;
                best_mem = row->mem_mib;
            }
        }
    }
    if (!found) return KSEC_ERR_INVALID;
    *ops_out = best_ops;
    *mem_mib_out = best_mem;
    return KSEC_OK;
}
