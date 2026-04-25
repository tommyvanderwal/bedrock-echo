// Witness packet dispatcher (ESP32, post-polish).
//
// Dispatch:
//   - DISCOVER → INIT (with cookie for src_ip, anti-amp 1.0× factor).
//   - BOOTSTRAP → cookie pre-check, then AEAD-decrypt cluster_key.
//   - HEARTBEAT → strict (src_ip, sender_id) match only. No
//     sender_id-only fallback, no new-node-join AEAD scan. Mismatches
//     get a rate-limited INIT reply.

#include "echo.h"
#include <string.h>
#include "esp_random.h"

// Outcome of a single AEAD trial in the dispatch chain.
typedef enum {
    HB_NOT_MINE = 0,   // AEAD failed under this cluster_key — try next
    HB_DROP,            // AEAD succeeded but packet should be silently dropped
    HB_REPLY,           // accepted; reply built into out
} hb_outcome_t;

static bool handle_discover(echo_state_t *state,
                             const uint8_t *data, size_t data_len,
                             const uint8_t src_ipv4[4], uint64_t now_ms,
                             uint8_t *out, size_t out_cap, size_t *out_len);
static bool handle_bootstrap(echo_state_t *state,
                              const uint8_t *data, size_t data_len,
                              const uint8_t src_ipv4[4], uint16_t src_port,
                              uint64_t now_ms,
                              uint8_t *out, size_t out_cap, size_t *out_len);
static bool handle_heartbeat(echo_state_t *state,
                              const uint8_t *data, size_t data_len,
                              const uint8_t src_ipv4[4], uint16_t src_port,
                              uint64_t now_ms,
                              uint8_t *out, size_t out_cap, size_t *out_len);

bool echo_handle_packet(echo_state_t *state,
                        const uint8_t *data, size_t data_len,
                        const uint8_t src_ipv4[4], uint16_t src_port,
                        uint64_t now_ms,
                        uint8_t *out, size_t out_cap, size_t *out_len) {
    if (data_len > ECHO_MTU_CAP || data_len < ECHO_HEADER_LEN) return false;
    echo_state_age_out(state, now_ms);
    // Lazy hourly cookie-secret rotation. esp_random.h provides a CSPRNG.
    if (echo_state_cookie_rotation_due(state, now_ms)) {
        uint8_t new_secret[ECHO_WITNESS_COOKIE_SECRET_LEN];
        esp_fill_random(new_secret, ECHO_WITNESS_COOKIE_SECRET_LEN);
        echo_state_maybe_rotate_cookie(state, now_ms, new_secret);
    }
    if (!echo_state_allow(state, src_ipv4, now_ms)) return false;

    echo_header_t hdr;
    if (echo_header_unpack(&hdr, data, data_len) != ECHO_OK) return false;

    switch (hdr.msg_type) {
        case ECHO_MSG_DISCOVER:
            return handle_discover(state, data, data_len, src_ipv4, now_ms,
                                    out, out_cap, out_len);
        case ECHO_MSG_BOOTSTRAP:
            return handle_bootstrap(state, data, data_len, src_ipv4, src_port, now_ms,
                                     out, out_cap, out_len);
        case ECHO_MSG_HEARTBEAT:
            return handle_heartbeat(state, data, data_len, src_ipv4, src_port, now_ms,
                                     out, out_cap, out_len);
        default:
            return false;
    }
}

// ─── DISCOVER ──────────────────────────────────────────────────────────────

static bool handle_discover(echo_state_t *state,
                             const uint8_t *data, size_t data_len,
                             const uint8_t src_ipv4[4], uint64_t now_ms,
                             uint8_t *out, size_t out_cap, size_t *out_len) {
    echo_header_t hdr;
    if (echo_decode_discover(data, data_len, &hdr) != ECHO_OK) return false;
    if (!echo_state_allow_unknown(state, src_ipv4, now_ms)) return false;
    int64_t ts_out = (int64_t)echo_state_uptime_ms(state, now_ms);
    uint8_t cookie[ECHO_COOKIE_LEN];
    echo_state_cookie_for(state, src_ipv4, cookie);
    return echo_encode_init(out, out_cap, out_len, ts_out,
                            state->witness_pub, cookie) == ECHO_OK;
}

// ─── BOOTSTRAP ─────────────────────────────────────────────────────────────

static bool handle_bootstrap(echo_state_t *state,
                              const uint8_t *data, size_t data_len,
                              const uint8_t src_ipv4[4], uint16_t src_port,
                              uint64_t now_ms,
                              uint8_t *out, size_t out_cap, size_t *out_len) {
    if (data_len != ECHO_BOOTSTRAP_LEN) return false;
    // Cookie pre-check (PROTOCOL.md §11.2). Cheap MAC; skip the AEAD/X25519
    // work on stale or forged cookies.
    const uint8_t *cookie_in = data + ECHO_HEADER_LEN;
    if (!echo_state_cookie_valid(state, src_ipv4, cookie_in)) return false;

    echo_header_t hdr;
    uint8_t cookie_dec[ECHO_COOKIE_LEN];
    uint8_t cluster_key[32];
    if (echo_decode_bootstrap(data, data_len, state->witness_priv,
                               &hdr, cookie_dec, cluster_key) != ECHO_OK) {
        return false;
    }
    (void)cookie_dec; // already pre-checked above; the AAD coverage is belt-and-suspenders
    uint64_t uptime_ms = echo_state_uptime_ms(state, now_ms);

    // Look for existing entry with same (sender_id, cluster_key).
    int existing_idx = -1;
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) {
        if (!state->nodes[i].in_use) continue;
        if (state->nodes[i].sender_id != hdr.sender_id) continue;
        uint16_t cs = state->nodes[i].cluster_slot;
        if (cs < ECHO_MAX_CLUSTERS
            && memcmp(state->clusters[cs].cluster_key, cluster_key, 32) == 0) {
            existing_idx = (int)i;
            break;
        }
    }

    uint16_t cluster_slot;
    uint8_t status;

    if (existing_idx >= 0) {
        cluster_slot = state->nodes[existing_idx].cluster_slot;
        if (!echo_state_adapt_offset(state, cluster_slot, hdr.timestamp_ms, uptime_ms))
            return false;
        echo_node_entry_t *n = &state->nodes[existing_idx];
        memcpy(n->sender_ipv4, src_ipv4, 4);
        n->sender_src_port = src_port;
        n->last_rx_ms = now_ms;
        if (hdr.timestamp_ms > n->last_rx_timestamp) {
            n->last_rx_timestamp = hdr.timestamp_ms;
        }
        status = 0x01;
    } else {
        // New entry. Either: brand-new cluster, or new node joining cluster,
        // or sender_id collision with another cluster.
        int existing_cluster = echo_state_find_cluster_by_key(state, cluster_key);
        int cs_int;
        if (existing_cluster >= 0) {
            cs_int = existing_cluster;
            if (!echo_state_adapt_offset(state, (uint16_t)cs_int,
                                          hdr.timestamp_ms, uptime_ms))
                return false;
        } else {
            cs_int = echo_state_alloc_cluster_slot(state);
            if (cs_int < 0) return false;
            echo_cluster_entry_t *c = &state->clusters[cs_int];
            c->in_use = true;
            memcpy(c->cluster_key, cluster_key, 32);
            c->bootstrapped_ms = now_ms;
            c->num_nodes = 0;
            c->cluster_offset = hdr.timestamp_ms - (int64_t)uptime_ms;
            c->last_tx_timestamp = 0;
        }
        cluster_slot = (uint16_t)cs_int;
        int ns_int = echo_state_alloc_node_slot(state);
        if (ns_int < 0) return false;
        echo_node_entry_t *n = &state->nodes[ns_int];
        n->in_use = true;
        n->sender_id = hdr.sender_id;
        memcpy(n->sender_ipv4, src_ipv4, 4);
        n->sender_src_port = src_port;
        n->cluster_slot = cluster_slot;
        n->last_rx_ms = now_ms;
        n->last_rx_timestamp = hdr.timestamp_ms;
        n->payload_first_block = 0;
        n->payload_n_blocks = 0;
        state->clusters[cluster_slot].num_nodes++;
        status = 0x00;
    }

    int64_t ts_out = echo_state_next_tx_ts(state, cluster_slot, uptime_ms);
    return echo_encode_bootstrap_ack(out, out_cap, out_len, ts_out, status,
                                      (uint32_t)(uptime_ms / 1000),
                                      state->clusters[cluster_slot].cluster_key) == ECHO_OK;
}

// ─── HEARTBEAT ─────────────────────────────────────────────────────────────

static bool build_heartbeat_reply(echo_state_t *state, uint16_t cluster_slot,
                                   uint8_t query_target_id, uint64_t uptime_ms,
                                   uint8_t *out, size_t out_cap, size_t *out_len) {
    int64_t ts_out = echo_state_next_tx_ts(state, cluster_slot, uptime_ms);
    uint32_t up_s = (uint32_t)(uptime_ms / 1000);
    const uint8_t *cluster_key = state->clusters[cluster_slot].cluster_key;

    if (query_target_id == ECHO_QUERY_LIST_SENTINEL) {
        echo_list_entry_t entries[ECHO_LIST_MAX_ENTRIES];
        size_t n = 0;
        int64_t cluster_now_ts = (int64_t)uptime_ms +
                                  state->clusters[cluster_slot].cluster_offset;
        for (size_t i = 0; i < ECHO_MAX_NODES && n < ECHO_LIST_MAX_ENTRIES; ++i) {
            if (!state->nodes[i].in_use) continue;
            if (state->nodes[i].cluster_slot != cluster_slot) continue;
            int64_t age = cluster_now_ts - state->nodes[i].last_rx_timestamp;
            if (age < 0) age = 0;
            uint32_t age_u32 = age > 0xFFFFFFFFLL ? 0xFFFFFFFFu : (uint32_t)age;
            entries[n].peer_sender_id = state->nodes[i].sender_id;
            entries[n].last_seen_ms = age_u32;
            n++;
        }
        // Sort by last_seen_ms ascending (most recent first). Insertion sort.
        for (size_t i = 1; i < n; ++i) {
            echo_list_entry_t tmp = entries[i];
            size_t j = i;
            while (j > 0 && entries[j - 1].last_seen_ms > tmp.last_seen_ms) {
                entries[j] = entries[j - 1]; j--;
            }
            entries[j] = tmp;
        }
        return echo_encode_status_list(out, out_cap, out_len, ts_out, up_s,
                                        entries, n, cluster_key) == ECHO_OK;
    }

    // STATUS_DETAIL for `query_target_id` in this cluster.
    int target = -1;
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) {
        if (state->nodes[i].in_use
            && state->nodes[i].cluster_slot == cluster_slot
            && state->nodes[i].sender_id == query_target_id) {
            target = (int)i;
            break;
        }
    }
    if (target < 0) {
        return echo_encode_status_detail_not_found(out, out_cap, out_len,
                                                    ts_out, up_s,
                                                    query_target_id,
                                                    cluster_key) == ECHO_OK;
    }
    int64_t cluster_now_ts = (int64_t)uptime_ms + state->clusters[cluster_slot].cluster_offset;
    int64_t age = cluster_now_ts - state->nodes[target].last_rx_timestamp;
    if (age < 0) age = 0;
    uint32_t age_u32 = age > 0xFFFFFFFFLL ? 0xFFFFFFFFu : (uint32_t)age;
    size_t pl_len = (size_t)state->nodes[target].payload_n_blocks * ECHO_PAYLOAD_BLOCK_SIZE;
    const uint8_t *payload =
        state->pool + (size_t)state->nodes[target].payload_first_block * ECHO_PAYLOAD_BLOCK_SIZE;
    return echo_encode_status_detail_found(out, out_cap, out_len, ts_out, up_s,
                                            query_target_id,
                                            state->nodes[target].sender_ipv4,
                                            age_u32, payload, pl_len,
                                            cluster_key) == ECHO_OK;
}

// Allocate blocks (with defrag fallback) and copy payload into the pool.
// Returns true on success. Updates *out_first and *out_n_blocks.
static bool allocate_payload(echo_state_t *state, const uint8_t *payload,
                              size_t payload_len, uint16_t *out_first,
                              uint8_t *out_n_blocks) {
    if (payload_len == 0) {
        *out_first = 0; *out_n_blocks = 0; return true;
    }
    uint8_t n_blocks = (uint8_t)(payload_len / ECHO_PAYLOAD_BLOCK_SIZE);
    int16_t first = echo_pool_alloc(state, n_blocks);
    if (first < 0) {
        // Try defrag and retry.
        echo_pool_defrag(state);
        first = echo_pool_alloc(state, n_blocks);
    }
    if (first < 0) return false;
    memcpy(state->pool + (size_t)first * ECHO_PAYLOAD_BLOCK_SIZE,
           payload, payload_len);
    *out_first = (uint16_t)first;
    *out_n_blocks = n_blocks;
    return true;
}

static hb_outcome_t try_existing_node(echo_state_t *state,
                                       const uint8_t *data, size_t data_len,
                                       const uint8_t src_ipv4[4], uint16_t src_port,
                                       uint64_t now_ms,
                                       size_t node_idx, uint16_t cluster_slot,
                                       const uint8_t cluster_key[32],
                                       uint8_t *out, size_t out_cap, size_t *out_len) {
    echo_header_t hdr;
    uint8_t qt;
    static uint8_t pt_scratch[ECHO_PAYLOAD_MAX_BYTES + 2];
    const uint8_t *payload;
    size_t payload_len;
    if (echo_decode_heartbeat(data, data_len, cluster_key, &hdr, &qt,
                               pt_scratch, sizeof(pt_scratch),
                               &payload, &payload_len) != ECHO_OK) {
        return HB_NOT_MINE;
    }

    // AEAD succeeded → this packet IS for this cluster. Anything below is Drop.
    if (hdr.timestamp_ms <= state->nodes[node_idx].last_rx_timestamp) return HB_DROP;
    uint64_t uptime_ms = echo_state_uptime_ms(state, now_ms);
    if (!echo_state_adapt_offset(state, cluster_slot, hdr.timestamp_ms, uptime_ms))
        return HB_DROP;

    // Update payload (re-allocate if size changed).
    echo_node_entry_t *n = &state->nodes[node_idx];
    uint8_t new_n_blocks = (uint8_t)(payload_len / ECHO_PAYLOAD_BLOCK_SIZE);
    if (new_n_blocks != n->payload_n_blocks) {
        // Free old by clearing and re-allocate.
        n->payload_n_blocks = 0;
        uint16_t first; uint8_t blocks;
        if (!allocate_payload(state, payload, payload_len, &first, &blocks))
            return HB_DROP;
        n->payload_first_block = first;
        n->payload_n_blocks = blocks;
    } else if (payload_len > 0) {
        // Same size: just overwrite in place.
        memcpy(state->pool + (size_t)n->payload_first_block * ECHO_PAYLOAD_BLOCK_SIZE,
               payload, payload_len);
    }
    memcpy(n->sender_ipv4, src_ipv4, 4);
    n->sender_src_port = src_port;
    n->last_rx_ms = now_ms;
    n->last_rx_timestamp = hdr.timestamp_ms;

    return build_heartbeat_reply(state, cluster_slot, qt, uptime_ms,
                                  out, out_cap, out_len) ? HB_REPLY : HB_DROP;
}

static bool handle_heartbeat(echo_state_t *state,
                              const uint8_t *data, size_t data_len,
                              const uint8_t src_ipv4[4], uint16_t src_port,
                              uint64_t now_ms,
                              uint8_t *out, size_t out_cap, size_t *out_len) {
    echo_header_t hdr;
    if (echo_header_unpack(&hdr, data, data_len) != ECHO_OK) return false;
    uint8_t sid = hdr.sender_id;

    // Strict (src_ip, sender_id) match only. No sender_id-only fallback,
    // no new-node-join scan — both removed in polish.
    for (size_t i = 0; i < ECHO_MAX_NODES; ++i) {
        if (!state->nodes[i].in_use) continue;
        if (state->nodes[i].sender_id != sid) continue;
        if (memcmp(state->nodes[i].sender_ipv4, src_ipv4, 4) != 0) continue;

        uint16_t cs = state->nodes[i].cluster_slot;
        const uint8_t *ck = state->clusters[cs].cluster_key;
        hb_outcome_t r = try_existing_node(state, data, data_len, src_ipv4, src_port,
                                            now_ms, i, cs, ck,
                                            out, out_cap, out_len);
        if (r == HB_REPLY) return true;
        // HB_NOT_MINE or HB_DROP both end the dispatch — there can only
        // be one (src_ip, sender_id) entry, so no other candidate to try.
        return false;
    }

    // No entry. Reply INIT (with fresh cookie) so caller can re-BOOTSTRAP.
    if (!echo_state_allow_unknown(state, src_ipv4, now_ms)) return false;
    int64_t ts_out = (int64_t)echo_state_uptime_ms(state, now_ms);
    uint8_t cookie[ECHO_COOKIE_LEN];
    echo_state_cookie_for(state, src_ipv4, cookie);
    return echo_encode_init(out, out_cap, out_len, ts_out,
                            state->witness_pub, cookie) == ECHO_OK;
}
