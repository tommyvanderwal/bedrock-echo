// RAM-only state tables + age-out + rate limiting. Fixed-size arrays, no malloc.

#include "echo.h"

#include <string.h>

#include "esp_system.h"
#include "mbedtls/sha256.h"

static void default_sender_id(const uint8_t pub[32], uint8_t out[8]) {
    uint8_t hash[32];
    mbedtls_sha256(pub, 32, hash, 0);
    memcpy(out, hash, 8);
}

void echo_state_init(echo_state_t *state, const uint8_t priv[32], uint64_t now_ms) {
    memset(state, 0, sizeof(*state));
    memcpy(state->witness_priv, priv, 32);
    echo_x25519_pub_from_priv(priv, state->witness_pub);
    default_sender_id(state->witness_pub, state->witness_sender_id);
    state->start_ms = now_ms;
}

uint64_t echo_state_uptime_ms(const echo_state_t *state, uint64_t now_ms) {
    return now_ms >= state->start_ms ? (now_ms - state->start_ms) : 0;
}

static size_t count_nodes(const echo_state_t *state) {
    size_t n = 0;
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) if (state->nodes[i].in_use) n++;
    return n;
}

static uint64_t age_out_timeout_ms(size_t nodes_in_use) {
    if (nodes_in_use < 16) return 72ULL * 3600ULL * 1000ULL;      // 72h
    if (nodes_in_use <= 48) return 1ULL * 3600ULL * 1000ULL;      // 1h
    return 5ULL * 60ULL * 1000ULL;                                 // 5min
}

void echo_state_age_out(echo_state_t *state, uint64_t now_ms) {
    size_t n = count_nodes(state);
    uint64_t timeout = age_out_timeout_ms(n);
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) {
        if (!state->nodes[i].in_use) continue;
        if (now_ms - state->nodes[i].last_rx_ms > timeout) {
            uint8_t cs = state->nodes[i].cluster_slot;
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

int echo_state_find_node(const echo_state_t *state, const uint8_t sender_id[8]) {
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) {
        if (state->nodes[i].in_use
            && memcmp(state->nodes[i].sender_id, sender_id, 8) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int echo_state_find_cluster_by_key(const echo_state_t *state,
                                   const uint8_t key[32]) {
    for (size_t i = 0; i < ECHO_MAX_CLUSTERS; ++i) {
        if (state->clusters[i].in_use
            && memcmp(state->clusters[i].cluster_key, key, 32) == 0) {
            return (int)i;
        }
    }
    return -1;
}

// ─── Rate limiting ──────────────────────────────────────────────────────────
#define RL_RATE_PER_SEC 10.0f
#define RL_BURST 20.0f
#define RL_UNKNOWN_MIN_INTERVAL_MS 1000ULL

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
    state->rate_limits[idx].tokens = RL_BURST;
    state->rate_limits[idx].last_refill_ms = now_ms;
    state->rate_limits[idx].last_unknown_ms = 0;
    return idx;
}

bool echo_state_allow(echo_state_t *state, const uint8_t ipv4[4], uint64_t now_ms) {
    int i = find_or_alloc_rate(state, ipv4, now_ms);
    echo_rate_entry_t *r = &state->rate_limits[i];
    uint64_t dt_ms = now_ms - r->last_refill_ms;
    float dt_s = (float)dt_ms / 1000.0f;
    r->tokens += dt_s * RL_RATE_PER_SEC;
    if (r->tokens > RL_BURST) r->tokens = RL_BURST;
    r->last_refill_ms = now_ms;
    if (r->tokens < 1.0f) return false;
    r->tokens -= 1.0f;
    return true;
}

bool echo_state_allow_unknown(echo_state_t *state, const uint8_t ipv4[4],
                              uint64_t now_ms) {
    int i = find_or_alloc_rate(state, ipv4, now_ms);
    echo_rate_entry_t *r = &state->rate_limits[i];
    if (now_ms - r->last_unknown_ms < RL_UNKNOWN_MIN_INTERVAL_MS) return false;
    r->last_unknown_ms = now_ms;
    return true;
}
