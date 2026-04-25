// Witness state + block allocator + age-out + rate limiting (ESP32 v1).
//
// State is fixed-size arrays (no malloc). Payloads live in `state->pool`,
// a 64 KB region of 32-byte blocks; node entries reference their payload
// by (first_block, n_blocks). The block allocator uses no bitmap — the
// node table itself is the allocation map.

#include "echo.h"
#include <stdlib.h>
#include <string.h>

// ─── State init ─────────────────────────────────────────────────────────────

#include "esp_random.h"

void echo_state_init(echo_state_t *state, const uint8_t priv[32], uint64_t now_ms) {
    memset(state, 0, sizeof(*state));
    memcpy(state->witness_priv, priv, 32);
    echo_x25519_pub_from_priv(priv, state->witness_pub);
    state->start_ms = now_ms;
    // Generate two random cookie secrets at boot (current + previous both
    // fresh, so any in-flight cookies from a previous witness session are
    // invalidated). esp_random.h provides a CSPRNG.
    esp_fill_random(state->cookie_current,  ECHO_WITNESS_COOKIE_SECRET_LEN);
    esp_fill_random(state->cookie_previous, ECHO_WITNESS_COOKIE_SECRET_LEN);
    state->last_cookie_rotation_ms = now_ms;
}

void echo_state_init_with_cookies(echo_state_t *state,
                                   const uint8_t priv[32],
                                   uint64_t now_ms,
                                   const uint8_t cookie_current[32],
                                   const uint8_t cookie_previous[32]) {
    memset(state, 0, sizeof(*state));
    memcpy(state->witness_priv, priv, 32);
    echo_x25519_pub_from_priv(priv, state->witness_pub);
    state->start_ms = now_ms;
    memcpy(state->cookie_current,  cookie_current,  32);
    memcpy(state->cookie_previous, cookie_previous, 32);
    state->last_cookie_rotation_ms = now_ms;
}

// ─── Cookie rotation + validation ──────────────────────────────────────────

bool echo_state_cookie_rotation_due(const echo_state_t *state, uint64_t now_ms) {
    return (now_ms - state->last_cookie_rotation_ms) >= ECHO_COOKIE_ROTATION_MS;
}

void echo_state_maybe_rotate_cookie(echo_state_t *state, uint64_t now_ms,
                                    const uint8_t new_secret[32]) {
    if (!echo_state_cookie_rotation_due(state, now_ms)) return;
    memcpy(state->cookie_previous, state->cookie_current, 32);
    memcpy(state->cookie_current,  new_secret,            32);
    state->last_cookie_rotation_ms = now_ms;
}

void echo_state_cookie_for(const echo_state_t *state,
                            const uint8_t src_ip[4],
                            uint8_t out[ECHO_COOKIE_LEN]) {
    echo_derive_cookie(state->cookie_current, src_ip, out);
}

bool echo_state_cookie_valid(const echo_state_t *state,
                              const uint8_t src_ip[4],
                              const uint8_t cookie[ECHO_COOKIE_LEN]) {
    uint8_t expected[ECHO_COOKIE_LEN];
    echo_derive_cookie(state->cookie_current, src_ip, expected);
    if (memcmp(cookie, expected, ECHO_COOKIE_LEN) == 0) return true;
    echo_derive_cookie(state->cookie_previous, src_ip, expected);
    return memcmp(cookie, expected, ECHO_COOKIE_LEN) == 0;
}

uint64_t echo_state_uptime_ms(const echo_state_t *state, uint64_t now_ms) {
    return now_ms >= state->start_ms ? (now_ms - state->start_ms) : 0;
}

// ─── Cluster table ──────────────────────────────────────────────────────────

int echo_state_find_cluster_by_key(const echo_state_t *state, const uint8_t key[32]) {
    for (size_t i = 0; i < ECHO_MAX_CLUSTERS; ++i) {
        if (state->clusters[i].in_use
            && memcmp(state->clusters[i].cluster_key, key, 32) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int echo_state_alloc_cluster_slot(const echo_state_t *state) {
    for (size_t i = 0; i < ECHO_MAX_CLUSTERS; ++i) {
        if (!state->clusters[i].in_use) return (int)i;
    }
    return -1;
}

int echo_state_alloc_node_slot(const echo_state_t *state) {
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) {
        if (!state->nodes[i].in_use) return (int)i;
    }
    return -1;
}

// ─── Per-cluster offset adaptation (PROTOCOL.md §6.2) ──────────────────────

bool echo_state_adapt_offset(echo_state_t *state, uint16_t cluster_slot,
                              int64_t pkt_ts, uint64_t uptime_ms) {
    echo_cluster_entry_t *c = &state->clusters[cluster_slot];
    int64_t expected = (int64_t)uptime_ms + c->cluster_offset;
    int64_t delta = pkt_ts - expected;
    if (delta > 0) {
        c->cluster_offset += delta;
    } else if (delta > -ECHO_MAX_BACKWARD_JUMP_MS) {
        int64_t step = delta < -ECHO_MAX_BACKWARD_STEP_MS ? -ECHO_MAX_BACKWARD_STEP_MS : delta;
        c->cluster_offset += step;
    } else {
        return false;
    }
    return true;
}

int64_t echo_state_next_tx_ts(echo_state_t *state, uint16_t cluster_slot,
                               uint64_t uptime_ms) {
    echo_cluster_entry_t *c = &state->clusters[cluster_slot];
    int64_t candidate = (int64_t)uptime_ms + c->cluster_offset;
    int64_t ts = candidate > c->last_tx_timestamp + 1 ? candidate : c->last_tx_timestamp + 1;
    c->last_tx_timestamp = ts;
    return ts;
}

// ─── Block allocator (no bitmap; node table is the allocation map) ─────────

typedef struct {
    uint16_t start;
    uint16_t end;  // exclusive
} interval_t;

static int interval_cmp(const void *a, const void *b) {
    const interval_t *ia = a, *ib = b;
    if (ia->start < ib->start) return -1;
    if (ia->start > ib->start) return 1;
    return 0;
}

int16_t echo_pool_alloc(echo_state_t *state, uint16_t n_blocks) {
    if (n_blocks == 0) return 0;
    if (n_blocks > ECHO_POOL_BLOCKS) return -1;

    // Build sorted list of in-use intervals from the node table.
    interval_t used[ECHO_MAX_NODES];
    size_t n = 0;
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) {
        if (state->nodes[i].in_use && state->nodes[i].payload_n_blocks > 0) {
            used[n].start = state->nodes[i].payload_first_block;
            used[n].end = state->nodes[i].payload_first_block + state->nodes[i].payload_n_blocks;
            n++;
        }
    }
    qsort(used, n, sizeof(interval_t), interval_cmp);

    uint16_t cursor = 0;
    for (size_t i = 0; i < n; ++i) {
        if (used[i].start - cursor >= n_blocks) {
            return (int16_t)cursor;
        }
        cursor = used[i].end;
    }
    if (ECHO_POOL_BLOCKS - cursor >= n_blocks) {
        return (int16_t)cursor;
    }
    return -1;
}

void echo_pool_free(echo_state_t *state, uint16_t first, uint16_t n) {
    (void)state; (void)first; (void)n;
    // No-op: deallocation is implicit when the node entry's in_use=false
    // or its (first_block, n_blocks) is rewritten. The allocator computes
    // free space from the live node table on every call.
}

void echo_pool_defrag(echo_state_t *state) {
    // Sort node indices by current first_block; shift each one down to
    // the cursor. memmove handles overlap (we always shift toward lower
    // addresses).
    uint16_t order[ECHO_MAX_NODES];
    size_t n = 0;
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) {
        if (state->nodes[i].in_use && state->nodes[i].payload_n_blocks > 0) {
            order[n++] = (uint16_t)i;
        }
    }
    // Selection sort on `order` by first_block (small N).
    for (size_t i = 0; i + 1 < n; ++i) {
        size_t min = i;
        for (size_t j = i + 1; j < n; ++j) {
            if (state->nodes[order[j]].payload_first_block <
                state->nodes[order[min]].payload_first_block) {
                min = j;
            }
        }
        uint16_t t = order[i]; order[i] = order[min]; order[min] = t;
    }

    uint16_t cursor = 0;
    for (size_t i = 0; i < n; ++i) {
        echo_node_entry_t *e = &state->nodes[order[i]];
        if (e->payload_first_block > cursor) {
            memmove(state->pool + (size_t)cursor * ECHO_PAYLOAD_BLOCK_SIZE,
                    state->pool + (size_t)e->payload_first_block * ECHO_PAYLOAD_BLOCK_SIZE,
                    (size_t)e->payload_n_blocks * ECHO_PAYLOAD_BLOCK_SIZE);
            e->payload_first_block = cursor;
        }
        cursor += e->payload_n_blocks;
    }
}

size_t echo_pool_blocks_in_use(const echo_state_t *state) {
    size_t total = 0;
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) {
        if (state->nodes[i].in_use) total += state->nodes[i].payload_n_blocks;
    }
    return total;
}

// ─── Age-out (PROTOCOL.md §10) ─────────────────────────────────────────────

static uint64_t age_out_timeout_ms(size_t nodes_in_use, size_t blocks_in_use) {
    // Tier triggered by the more-aggressive of node-table fill and pool fill.
    const size_t node_80 = (ECHO_MAX_NODES * 80u) / 100u;
    const size_t node_90 = (ECHO_MAX_NODES * 90u) / 100u;
    const size_t pool_80 = (ECHO_POOL_BLOCKS * 80u) / 100u;
    const size_t pool_90 = (ECHO_POOL_BLOCKS * 90u) / 100u;
    bool over_90 = nodes_in_use > node_90 || blocks_in_use > pool_90;
    bool over_80 = nodes_in_use > node_80 || blocks_in_use > pool_80;
    if (over_90) return 5ULL * 60ULL * 1000ULL;
    if (over_80) return 4ULL * 3600ULL * 1000ULL;
    return 72ULL * 3600ULL * 1000ULL;
}

void echo_state_age_out(echo_state_t *state, uint64_t now_ms) {
    size_t n = 0;
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) if (state->nodes[i].in_use) n++;
    size_t blocks = echo_pool_blocks_in_use(state);
    uint64_t timeout = age_out_timeout_ms(n, blocks);
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) {
        if (!state->nodes[i].in_use) continue;
        if (now_ms - state->nodes[i].last_rx_ms > timeout) {
            uint16_t cs = state->nodes[i].cluster_slot;
            state->nodes[i].in_use = false;
            if (cs < ECHO_MAX_CLUSTERS && state->clusters[cs].in_use) {
                if (state->clusters[cs].num_nodes > 0)
                    state->clusters[cs].num_nodes--;
                if (state->clusters[cs].num_nodes == 0)
                    state->clusters[cs].in_use = false;
            }
        }
    }
}

// ─── Rate limiting ──────────────────────────────────────────────────────────

static int find_or_alloc_rate(echo_state_t *state, const uint8_t ipv4[4],
                              uint64_t now_ms) {
    int free_idx = -1;
    int oldest_idx = 0;
    uint64_t oldest_refill = state->rate_limits[0].last_refill_ms;
    for (size_t i = 0; i < ECHO_MAX_TRACKED_IPS; ++i) {
        if (state->rate_limits[i].in_use
            && memcmp(state->rate_limits[i].ipv4, ipv4, 4) == 0) {
            return (int)i;
        }
        if (!state->rate_limits[i].in_use && free_idx == -1) free_idx = (int)i;
        if (state->rate_limits[i].last_refill_ms < oldest_refill) {
            oldest_refill = state->rate_limits[i].last_refill_ms;
            oldest_idx = (int)i;
        }
    }
    int idx = free_idx != -1 ? free_idx : oldest_idx;
    state->rate_limits[idx].in_use = true;
    memcpy(state->rate_limits[idx].ipv4, ipv4, 4);
    state->rate_limits[idx].tokens = ECHO_RL_BURST;
    state->rate_limits[idx].last_refill_ms = now_ms;
    state->rate_limits[idx].last_unknown_ms = 0;
    return idx;
}

bool echo_state_allow(echo_state_t *state, const uint8_t ipv4[4], uint64_t now_ms) {
    int i = find_or_alloc_rate(state, ipv4, now_ms);
    echo_rate_entry_t *r = &state->rate_limits[i];
    uint64_t dt_ms = now_ms - r->last_refill_ms;
    float dt_s = (float)dt_ms / 1000.0f;
    r->tokens += dt_s * ECHO_RL_RATE_PER_SEC;
    if (r->tokens > ECHO_RL_BURST) r->tokens = ECHO_RL_BURST;
    r->last_refill_ms = now_ms;
    if (r->tokens < 1.0f) return false;
    r->tokens -= 1.0f;
    return true;
}

bool echo_state_allow_unknown(echo_state_t *state, const uint8_t ipv4[4],
                               uint64_t now_ms) {
    int i = find_or_alloc_rate(state, ipv4, now_ms);
    echo_rate_entry_t *r = &state->rate_limits[i];
    if (now_ms - r->last_unknown_ms < ECHO_RL_UNKNOWN_INTERVAL_MS) return false;
    r->last_unknown_ms = now_ms;
    return true;
}
