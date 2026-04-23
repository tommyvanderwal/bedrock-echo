// Packet dispatcher — mirrors crates/bedrock-echo-witness/src/handler.rs
// and python/echo/witness.py. Pure function: takes packet bytes + source IP
// + current time; returns reply bytes (or nothing).

#include "bew1.h"

#include <string.h>

// Decls for the encode/decode functions implemented in bew1_proto.c.
// Kept here (not in bew1.h) because they are internal to the witness and
// don't need to be part of the public API.

typedef struct {
    bew1_header_t hdr;
    uint8_t query_target_id[8];
    const uint8_t *own_payload;
    size_t own_payload_len;
} bew1_heartbeat_view_t;

bew1_err_t bew1_decode_heartbeat(bew1_heartbeat_view_t *out,
                                  const uint8_t *buf, size_t len,
                                  const uint8_t *cluster_key);

typedef struct {
    bew1_header_t hdr;
    uint8_t cluster_key[BEW1_CLUSTER_KEY_LEN];
    uint8_t init_payload[BEW1_BOOTSTRAP_INIT_PAYLOAD_MAX];
    size_t init_payload_len;
} bew1_bootstrap_view_t;

bew1_err_t bew1_decode_bootstrap(bew1_bootstrap_view_t *out,
                                  const uint8_t *buf, size_t len,
                                  const uint8_t witness_priv[32]);

typedef struct {
    uint8_t peer_sender_id[8];
    uint8_t peer_ipv4[4];
    uint32_t last_seen_seconds;
} bew1_list_entry_t;

bew1_err_t bew1_encode_status_list(uint8_t *out, size_t out_cap, size_t *out_len,
                                    const uint8_t sender_id[8], uint64_t seq,
                                    int64_t ts_ms, uint64_t witness_uptime_ms,
                                    const bew1_list_entry_t *entries, size_t n_entries,
                                    const uint8_t *cluster_key);

bew1_err_t bew1_encode_status_detail_found(
    uint8_t *out, size_t out_cap, size_t *out_len,
    const uint8_t sender_id[8], uint64_t seq, int64_t ts_ms,
    uint64_t witness_uptime_ms,
    const uint8_t target_sender_id[8],
    const uint8_t peer_ipv4[4], uint32_t last_seen_seconds,
    const uint8_t *peer_payload, size_t peer_payload_len,
    const uint8_t *cluster_key);

bew1_err_t bew1_encode_status_detail_not_found(
    uint8_t *out, size_t out_cap, size_t *out_len,
    const uint8_t sender_id[8], uint64_t seq, int64_t ts_ms,
    uint64_t witness_uptime_ms, const uint8_t target_sender_id[8],
    const uint8_t *cluster_key);

bew1_err_t bew1_encode_unknown_source(uint8_t *out, size_t out_cap, size_t *out_len,
                                       const uint8_t sender_id[8],
                                       uint64_t seq, int64_t ts_ms);

bew1_err_t bew1_encode_bootstrap_ack(uint8_t *out, size_t out_cap, size_t *out_len,
                                      const uint8_t sender_id[8],
                                      uint64_t seq, int64_t ts_ms,
                                      uint8_t status, uint64_t witness_uptime_ms,
                                      const uint8_t *cluster_key);

// ─── Helpers ────────────────────────────────────────────────────────────────

static int allocate_cluster_slot(bew1_state_t *state) {
    for (size_t i = 0; i < BEW1_MAX_CLUSTERS; ++i)
        if (!state->clusters[i].in_use) return (int)i;
    return -1;
}

static int allocate_node_slot(bew1_state_t *state) {
    for (size_t i = 0; i < BEW1_MAX_NODES; ++i)
        if (!state->nodes[i].in_use) return (int)i;
    return -1;
}

static uint64_t next_tx_seq(bew1_node_entry_t *n, uint64_t now_ms) {
    uint64_t next = now_ms > n->last_tx_sequence + 1 ? now_ms : n->last_tx_sequence + 1;
    n->last_tx_sequence = next;
    return next;
}

// Rate-limited UNKNOWN_SOURCE reply — §4.4.
static bool maybe_unknown_source(bew1_state_t *state, const uint8_t ipv4[4],
                                  uint64_t now_ms,
                                  uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!bew1_state_allow_unknown(state, ipv4, now_ms)) return false;
    return bew1_encode_unknown_source(out, out_cap, out_len,
                                       state->witness_sender_id,
                                       now_ms, (int64_t)now_ms) == BEW1_OK;
}

// ─── Bootstrap ──────────────────────────────────────────────────────────────

static bool handle_bootstrap(bew1_state_t *state,
                              const uint8_t *data, size_t data_len,
                              const uint8_t src_ipv4[4], uint64_t now_ms,
                              uint8_t *out, size_t out_cap, size_t *out_len) {
    bew1_bootstrap_view_t bs;
    if (bew1_decode_bootstrap(&bs, data, data_len, state->witness_priv) != BEW1_OK)
        return false;  // silent drop

    int existing_idx = bew1_state_find_node(state, bs.hdr.sender_id);
    uint8_t status;
    int cluster_slot;

    if (existing_idx >= 0) {
        uint8_t cs = state->nodes[existing_idx].cluster_slot;
        if (cs >= BEW1_MAX_CLUSTERS || !state->clusters[cs].in_use) return false;
        if (memcmp(state->clusters[cs].cluster_key, bs.cluster_key, 32) != 0) {
            // Same sender_id, different cluster_key — silent drop (§4.6).
            return false;
        }
        // Idempotent re-bootstrap.
        state->nodes[existing_idx].last_rx_ms = now_ms;
        state->nodes[existing_idx].last_rx_sequence = 0;
        state->nodes[existing_idx].last_tx_sequence = 0;
        memcpy(state->nodes[existing_idx].sender_ipv4, src_ipv4, 4);
        cluster_slot = cs;
        status = 0x01;
    } else {
        // New node.
        int ns = allocate_node_slot(state);
        if (ns < 0) return false;
        int cs = bew1_state_find_cluster_by_key(state, bs.cluster_key);
        if (cs < 0) {
            cs = allocate_cluster_slot(state);
            if (cs < 0) return false;
            memset(&state->clusters[cs], 0, sizeof(state->clusters[cs]));
            state->clusters[cs].in_use = true;
            memcpy(state->clusters[cs].cluster_key, bs.cluster_key, 32);
            state->clusters[cs].bootstrapped_ms = now_ms;
        }
        cluster_slot = cs;
        memset(&state->nodes[ns], 0, sizeof(state->nodes[ns]));
        state->nodes[ns].in_use = true;
        memcpy(state->nodes[ns].sender_id, bs.hdr.sender_id, 8);
        memcpy(state->nodes[ns].sender_ipv4, src_ipv4, 4);
        state->nodes[ns].cluster_slot = (uint8_t)cs;
        state->nodes[ns].last_rx_ms = now_ms;
        state->nodes[ns].payload_len = (uint8_t)bs.init_payload_len;
        if (bs.init_payload_len)
            memcpy(state->nodes[ns].payload, bs.init_payload, bs.init_payload_len);
        state->clusters[cs].num_nodes++;
        existing_idx = ns;
        status = 0x00;
    }

    const uint8_t *ckey = state->clusters[cluster_slot].cluster_key;
    uint64_t seq = next_tx_seq(&state->nodes[existing_idx], now_ms);
    return bew1_encode_bootstrap_ack(out, out_cap, out_len,
                                      state->witness_sender_id,
                                      seq, (int64_t)now_ms,
                                      status,
                                      bew1_state_uptime_ms(state, now_ms),
                                      ckey) == BEW1_OK;
}

// ─── Heartbeat ──────────────────────────────────────────────────────────────

static bool handle_heartbeat(bew1_state_t *state,
                              const uint8_t *data, size_t data_len,
                              const uint8_t src_ipv4[4], uint64_t now_ms,
                              uint8_t *out, size_t out_cap, size_t *out_len) {
    bew1_header_t hdr;
    if (bew1_header_unpack(&hdr, data, data_len) != BEW1_OK) return false;

    int node_idx = bew1_state_find_node(state, hdr.sender_id);
    if (node_idx < 0) {
        return maybe_unknown_source(state, src_ipv4, now_ms, out, out_cap, out_len);
    }
    uint8_t cs = state->nodes[node_idx].cluster_slot;
    if (cs >= BEW1_MAX_CLUSTERS || !state->clusters[cs].in_use) {
        state->nodes[node_idx].in_use = false;
        return maybe_unknown_source(state, src_ipv4, now_ms, out, out_cap, out_len);
    }
    const uint8_t *ckey = state->clusters[cs].cluster_key;

    bew1_heartbeat_view_t hb;
    bew1_err_t e = bew1_decode_heartbeat(&hb, data, data_len, ckey);
    if (e == BEW1_ERR_AUTH_FAILED) {
        return maybe_unknown_source(state, src_ipv4, now_ms, out, out_cap, out_len);
    }
    if (e != BEW1_OK) return false;

    if (hb.hdr.sequence <= state->nodes[node_idx].last_rx_sequence)
        return false;  // replay

    state->nodes[node_idx].last_rx_sequence = hb.hdr.sequence;
    state->nodes[node_idx].last_rx_ms = now_ms;
    memcpy(state->nodes[node_idx].sender_ipv4, src_ipv4, 4);
    state->nodes[node_idx].payload_len = (uint8_t)hb.own_payload_len;
    if (hb.own_payload_len)
        memcpy(state->nodes[node_idx].payload, hb.own_payload, hb.own_payload_len);

    uint64_t uptime = bew1_state_uptime_ms(state, now_ms);
    uint64_t seq = next_tx_seq(&state->nodes[node_idx], now_ms);

    // Reply branch: zero target = LIST, non-zero = DETAIL.
    static const uint8_t zero8[8] = {0};
    if (memcmp(hb.query_target_id, zero8, 8) == 0) {
        // STATUS_LIST: every node entry in the same cluster.
        bew1_list_entry_t entries[BEW1_MAX_NODES];
        size_t n = 0;
        for (size_t i = 0; i < BEW1_MAX_NODES; ++i) {
            if (state->nodes[i].in_use
                && state->nodes[i].cluster_slot == cs
                && n < BEW1_LIST_MAX_ENTRIES) {
                memcpy(entries[n].peer_sender_id, state->nodes[i].sender_id, 8);
                memcpy(entries[n].peer_ipv4, state->nodes[i].sender_ipv4, 4);
                uint64_t age_ms = now_ms - state->nodes[i].last_rx_ms;
                uint32_t age_s = (uint32_t)(age_ms / 1000ULL);
                entries[n].last_seen_seconds = age_s;
                n++;
            }
        }
        // Insertion-sort by last_seen_seconds ascending (stable, n ≤ 64).
        for (size_t i = 1; i < n; ++i) {
            bew1_list_entry_t tmp = entries[i];
            size_t j = i;
            while (j > 0 && entries[j - 1].last_seen_seconds > tmp.last_seen_seconds) {
                entries[j] = entries[j - 1]; j--;
            }
            entries[j] = tmp;
        }
        return bew1_encode_status_list(out, out_cap, out_len,
                                        state->witness_sender_id, seq,
                                        (int64_t)now_ms, uptime, entries, n,
                                        ckey) == BEW1_OK;
    } else {
        int tgt = -1;
        for (size_t i = 0; i < BEW1_MAX_NODES; ++i) {
            if (state->nodes[i].in_use
                && state->nodes[i].cluster_slot == cs
                && memcmp(state->nodes[i].sender_id, hb.query_target_id, 8) == 0) {
                tgt = (int)i;
                break;
            }
        }
        if (tgt < 0) {
            return bew1_encode_status_detail_not_found(
                out, out_cap, out_len, state->witness_sender_id, seq,
                (int64_t)now_ms, uptime, hb.query_target_id, ckey) == BEW1_OK;
        }
        uint32_t age_s = (uint32_t)((now_ms - state->nodes[tgt].last_rx_ms) / 1000ULL);
        return bew1_encode_status_detail_found(
            out, out_cap, out_len, state->witness_sender_id, seq,
            (int64_t)now_ms, uptime, hb.query_target_id,
            state->nodes[tgt].sender_ipv4, age_s,
            state->nodes[tgt].payload, state->nodes[tgt].payload_len,
            ckey) == BEW1_OK;
    }
}

// ─── Entry point ────────────────────────────────────────────────────────────

bool bew1_handle_packet(bew1_state_t *state,
                        const uint8_t *data, size_t data_len,
                        const uint8_t src_ipv4[4],
                        uint64_t now_ms,
                        uint8_t *out, size_t out_cap, size_t *out_len) {
    if (data_len > BEW1_MTU_CAP || data_len < BEW1_HEADER_LEN) return false;
    bew1_state_age_out(state, now_ms);
    if (!bew1_state_allow(state, src_ipv4, now_ms)) return false;

    bew1_header_t hdr;
    if (bew1_header_unpack(&hdr, data, data_len) != BEW1_OK) return false;
    uint8_t tl = bew1_trailer_len(hdr.msg_type);
    if (tl == 0xff) return false;
    if (data_len != (size_t)(BEW1_HEADER_LEN + hdr.payload_len + tl)) return false;

    switch (hdr.msg_type) {
        case BEW1_MSG_BOOTSTRAP:
            return handle_bootstrap(state, data, data_len, src_ipv4, now_ms,
                                    out, out_cap, out_len);
        case BEW1_MSG_HEARTBEAT:
            return handle_heartbeat(state, data, data_len, src_ipv4, now_ms,
                                    out, out_cap, out_len);
        default:
            return false;  // witness never receives STATUS/UNKNOWN/ACK
    }
}
