// Echo header + per-msg-type encode/decode helpers.
// Byte-for-byte match with python/echo/proto.py and crates/bedrock-echo-proto.

#include "echo.h"
#include <string.h>

static inline void w_u16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static inline uint16_t r_u16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static inline void w_u32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}
static inline uint32_t r_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}
static inline void w_u64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; --i) { p[7 - i] = (v >> (i * 8)) & 0xff; }
}
static inline uint64_t r_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

uint8_t echo_trailer_len(uint8_t msg_type) {
    switch (msg_type) {
        case ECHO_MSG_HEARTBEAT:
        case ECHO_MSG_STATUS_LIST:
        case ECHO_MSG_STATUS_DETAIL:
        case ECHO_MSG_BOOTSTRAP_ACK:
            return ECHO_HMAC_LEN;
        case ECHO_MSG_UNKNOWN_SOURCE:
        case ECHO_MSG_BOOTSTRAP:
            return 0;
        default:
            return 0xff;
    }
}

bool echo_is_hmac_type(uint8_t msg_type) {
    switch (msg_type) {
        case ECHO_MSG_HEARTBEAT:
        case ECHO_MSG_STATUS_LIST:
        case ECHO_MSG_STATUS_DETAIL:
        case ECHO_MSG_BOOTSTRAP_ACK:
            return true;
        default:
            return false;
    }
}

echo_err_t echo_header_pack(uint8_t out[ECHO_HEADER_LEN], const echo_header_t *hdr) {
    memcpy(out, ECHO_MAGIC, 4);
    out[4] = hdr->msg_type;
    out[5] = hdr->flags;
    memcpy(out + 6, hdr->sender_id, 8);
    w_u64(out + 14, hdr->sequence);
    w_u64(out + 22, (uint64_t)hdr->timestamp_ms);
    w_u16(out + 30, hdr->payload_len);
    return ECHO_OK;
}

echo_err_t echo_header_unpack(echo_header_t *out, const uint8_t *buf, size_t len) {
    if (len < ECHO_HEADER_LEN) return ECHO_ERR_TOO_SHORT;
    if (memcmp(buf, ECHO_MAGIC, 4) != 0) return ECHO_ERR_BAD_MAGIC;
    out->msg_type = buf[4];
    out->flags = buf[5];
    if (out->flags != 0) return ECHO_ERR_BAD_FLAGS;
    uint8_t tl = echo_trailer_len(out->msg_type);
    if (tl == 0xff) return ECHO_ERR_BAD_MSG_TYPE;
    memcpy(out->sender_id, buf + 6, 8);
    out->sequence = r_u64(buf + 14);
    out->timestamp_ms = (int64_t)r_u64(buf + 22);
    out->payload_len = r_u16(buf + 30);
    return ECHO_OK;
}

// ─── HMAC helpers ───────────────────────────────────────────────────────────
static void finalize_hmac(uint8_t *buf, size_t body_len, const uint8_t *key) {
    uint8_t tag[32];
    echo_hmac_sha256(key, ECHO_CLUSTER_KEY_LEN, buf, body_len, tag);
    memcpy(buf + body_len, tag, 32);
}

// Returns true iff trailer verifies.
static bool verify_hmac(const uint8_t *buf, size_t total_len, const uint8_t *key) {
    if (total_len < 32) return false;
    size_t body_len = total_len - 32;
    return echo_hmac_verify(key, ECHO_CLUSTER_KEY_LEN, buf, body_len, buf + body_len);
}

// ─── HEARTBEAT 0x01 ─────────────────────────────────────────────────────────
// Decoder used on witness; encoder isn't needed (only nodes send heartbeats).

typedef struct {
    echo_header_t hdr;
    uint8_t query_target_id[8];
    const uint8_t *own_payload;
    size_t own_payload_len;
} echo_heartbeat_view_t;

echo_err_t echo_decode_heartbeat(echo_heartbeat_view_t *out,
                                  const uint8_t *buf, size_t len,
                                  const uint8_t *cluster_key) {
    if (len > ECHO_MTU_CAP) return ECHO_ERR_OVER_MTU;
    if (!verify_hmac(buf, len, cluster_key)) return ECHO_ERR_AUTH_FAILED;
    echo_err_t e = echo_header_unpack(&out->hdr, buf, len);
    if (e != ECHO_OK) return e;
    if (out->hdr.msg_type != ECHO_MSG_HEARTBEAT) return ECHO_ERR_BAD_MSG_TYPE;
    if (len != (size_t)(ECHO_HEADER_LEN + out->hdr.payload_len + 32))
        return ECHO_ERR_BAD_LENGTH;
    size_t pl = out->hdr.payload_len;
    if (pl < 8 || pl > 8 + ECHO_NODE_PAYLOAD_MAX) return ECHO_ERR_BAD_PAYLOAD_LEN;
    static const uint8_t zero8[8] = {0};
    if (memcmp(out->hdr.sender_id, zero8, 8) == 0) return ECHO_ERR_ZERO_SENDER_ID;
    memcpy(out->query_target_id, buf + ECHO_HEADER_LEN, 8);
    out->own_payload = buf + ECHO_HEADER_LEN + 8;
    out->own_payload_len = pl - 8;
    return ECHO_OK;
}

// Forward-declared for internal use; definitions below.
echo_err_t echo_encode_heartbeat(uint8_t *out, size_t out_cap, size_t *out_len,
                                  const uint8_t sender_id[8], uint64_t seq,
                                  int64_t ts_ms, const uint8_t query[8],
                                  const uint8_t *own_payload, size_t own_len,
                                  const uint8_t *cluster_key);

echo_err_t echo_encode_heartbeat(uint8_t *out, size_t out_cap, size_t *out_len,
                                  const uint8_t sender_id[8], uint64_t seq,
                                  int64_t ts_ms, const uint8_t query[8],
                                  const uint8_t *own_payload, size_t own_len,
                                  const uint8_t *cluster_key) {
    if (own_len > ECHO_NODE_PAYLOAD_MAX) return ECHO_ERR_BAD_PAYLOAD_LEN;
    size_t pl = 8 + own_len;
    size_t total = ECHO_HEADER_LEN + pl + 32;
    if (total > ECHO_MTU_CAP) return ECHO_ERR_OVER_MTU;
    if (out_cap < total) return ECHO_ERR_BAD_LENGTH;
    echo_header_t h = {
        .msg_type = ECHO_MSG_HEARTBEAT, .flags = 0,
        .sequence = seq, .timestamp_ms = ts_ms,
        .payload_len = (uint16_t)pl,
    };
    memcpy(h.sender_id, sender_id, 8);
    echo_header_pack(out, &h);
    memcpy(out + ECHO_HEADER_LEN, query, 8);
    if (own_len) memcpy(out + ECHO_HEADER_LEN + 8, own_payload, own_len);
    finalize_hmac(out, ECHO_HEADER_LEN + pl, cluster_key);
    *out_len = total;
    return ECHO_OK;
}

// ─── STATUS_LIST 0x02 ───────────────────────────────────────────────────────
// Entry format: sender_id(8) + ipv4(4) + last_seen_seconds(u32) = 16 bytes.

typedef struct {
    uint8_t peer_sender_id[8];
    uint8_t peer_ipv4[4];
    uint32_t last_seen_seconds;
} echo_list_entry_t;

echo_err_t echo_encode_status_list(uint8_t *out, size_t out_cap, size_t *out_len,
                                    const uint8_t sender_id[8], uint64_t seq,
                                    int64_t ts_ms, uint64_t witness_uptime_ms,
                                    const echo_list_entry_t *entries, size_t n_entries,
                                    const uint8_t *cluster_key) {
    if (n_entries > ECHO_LIST_MAX_ENTRIES) return ECHO_ERR_BAD_PAYLOAD_LEN;
    size_t pl = 10 + n_entries * ECHO_LIST_ENTRY_LEN;
    size_t total = ECHO_HEADER_LEN + pl + 32;
    if (total > ECHO_MTU_CAP) return ECHO_ERR_OVER_MTU;
    if (out_cap < total) return ECHO_ERR_BAD_LENGTH;
    echo_header_t h = {
        .msg_type = ECHO_MSG_STATUS_LIST, .flags = 0,
        .sequence = seq, .timestamp_ms = ts_ms,
        .payload_len = (uint16_t)pl,
    };
    memcpy(h.sender_id, sender_id, 8);
    echo_header_pack(out, &h);
    uint8_t *p = out + ECHO_HEADER_LEN;
    w_u64(p, witness_uptime_ms); p += 8;
    *p++ = (uint8_t)n_entries;
    *p++ = 0;  // reserved
    for (size_t i = 0; i < n_entries; ++i) {
        memcpy(p, entries[i].peer_sender_id, 8); p += 8;
        memcpy(p, entries[i].peer_ipv4, 4); p += 4;
        w_u32(p, entries[i].last_seen_seconds); p += 4;
    }
    finalize_hmac(out, ECHO_HEADER_LEN + pl, cluster_key);
    *out_len = total;
    return ECHO_OK;
}

// ─── STATUS_DETAIL 0x03 ─────────────────────────────────────────────────────

echo_err_t echo_encode_status_detail_found(
    uint8_t *out, size_t out_cap, size_t *out_len,
    const uint8_t sender_id[8], uint64_t seq, int64_t ts_ms,
    uint64_t witness_uptime_ms,
    const uint8_t target_sender_id[8],
    const uint8_t peer_ipv4[4], uint32_t last_seen_seconds,
    const uint8_t *peer_payload, size_t peer_payload_len,
    const uint8_t *cluster_key) {
    if (peer_payload_len > ECHO_NODE_PAYLOAD_MAX) return ECHO_ERR_BAD_PAYLOAD_LEN;
    size_t pl = 27 + peer_payload_len;
    size_t total = ECHO_HEADER_LEN + pl + 32;
    if (total > ECHO_MTU_CAP) return ECHO_ERR_OVER_MTU;
    if (out_cap < total) return ECHO_ERR_BAD_LENGTH;
    echo_header_t h = {
        .msg_type = ECHO_MSG_STATUS_DETAIL, .flags = 0,
        .sequence = seq, .timestamp_ms = ts_ms,
        .payload_len = (uint16_t)pl,
    };
    memcpy(h.sender_id, sender_id, 8);
    echo_header_pack(out, &h);
    uint8_t *p = out + ECHO_HEADER_LEN;
    w_u64(p, witness_uptime_ms); p += 8;
    memcpy(p, target_sender_id, 8); p += 8;
    *p++ = 0x00;  // status: found
    *p++ = 0x00;  // reserved
    memcpy(p, peer_ipv4, 4); p += 4;
    w_u32(p, last_seen_seconds); p += 4;
    *p++ = (uint8_t)peer_payload_len;
    if (peer_payload_len) memcpy(p, peer_payload, peer_payload_len);
    finalize_hmac(out, ECHO_HEADER_LEN + pl, cluster_key);
    *out_len = total;
    return ECHO_OK;
}

echo_err_t echo_encode_status_detail_not_found(
    uint8_t *out, size_t out_cap, size_t *out_len,
    const uint8_t sender_id[8], uint64_t seq, int64_t ts_ms,
    uint64_t witness_uptime_ms, const uint8_t target_sender_id[8],
    const uint8_t *cluster_key) {
    size_t pl = 18;
    size_t total = ECHO_HEADER_LEN + pl + 32;
    if (out_cap < total) return ECHO_ERR_BAD_LENGTH;
    echo_header_t h = {
        .msg_type = ECHO_MSG_STATUS_DETAIL, .flags = 0,
        .sequence = seq, .timestamp_ms = ts_ms,
        .payload_len = (uint16_t)pl,
    };
    memcpy(h.sender_id, sender_id, 8);
    echo_header_pack(out, &h);
    uint8_t *p = out + ECHO_HEADER_LEN;
    w_u64(p, witness_uptime_ms); p += 8;
    memcpy(p, target_sender_id, 8); p += 8;
    *p++ = 0x01;
    *p++ = 0x00;
    finalize_hmac(out, ECHO_HEADER_LEN + pl, cluster_key);
    *out_len = total;
    return ECHO_OK;
}

// ─── UNKNOWN_SOURCE 0x10 (unauthenticated) ──────────────────────────────────

echo_err_t echo_encode_unknown_source(uint8_t *out, size_t out_cap, size_t *out_len,
                                       const uint8_t sender_id[8],
                                       uint64_t seq, int64_t ts_ms) {
    if (out_cap < ECHO_HEADER_LEN) return ECHO_ERR_BAD_LENGTH;
    echo_header_t h = {
        .msg_type = ECHO_MSG_UNKNOWN_SOURCE, .flags = 0,
        .sequence = seq, .timestamp_ms = ts_ms, .payload_len = 0,
    };
    memcpy(h.sender_id, sender_id, 8);
    echo_header_pack(out, &h);
    *out_len = ECHO_HEADER_LEN;
    return ECHO_OK;
}

// ─── BOOTSTRAP 0x20 (inbound on witness) ────────────────────────────────────

typedef struct {
    echo_header_t hdr;
    uint8_t cluster_key[ECHO_CLUSTER_KEY_LEN];
    uint8_t init_payload[ECHO_BOOTSTRAP_INIT_PAYLOAD_MAX];
    size_t init_payload_len;
} echo_bootstrap_view_t;

echo_err_t echo_decode_bootstrap(echo_bootstrap_view_t *out,
                                  const uint8_t *buf, size_t len,
                                  const uint8_t witness_priv[32]) {
    if (len > ECHO_MTU_CAP) return ECHO_ERR_OVER_MTU;
    echo_err_t e = echo_header_unpack(&out->hdr, buf, len);
    if (e != ECHO_OK) return e;
    if (out->hdr.msg_type != ECHO_MSG_BOOTSTRAP) return ECHO_ERR_BAD_MSG_TYPE;
    if (len != (size_t)(ECHO_HEADER_LEN + out->hdr.payload_len))
        return ECHO_ERR_BAD_LENGTH;
    size_t pl = out->hdr.payload_len;
    if (pl < 32 + 32 + 16) return ECHO_ERR_BAD_PAYLOAD_LEN;
    if (pl > 32 + 32 + ECHO_BOOTSTRAP_INIT_PAYLOAD_MAX + 16)
        return ECHO_ERR_BAD_PAYLOAD_LEN;
    const uint8_t *payload = buf + ECHO_HEADER_LEN;
    const uint8_t *eph_pub = payload;
    const uint8_t *ct = payload + 32;
    size_t ct_len = pl - 32;

    uint8_t shared[32];
    if (!echo_x25519_shared(witness_priv, eph_pub, shared))
        return ECHO_ERR_AUTH_FAILED;

    uint8_t derived[32];
    if (!echo_hkdf_sha256(shared, 32, derived))
        return ECHO_ERR_AUTH_FAILED;

    // AAD = packet header bytes [0..32]. Decrypt into a local plaintext buffer.
    uint8_t plaintext[32 + ECHO_BOOTSTRAP_INIT_PAYLOAD_MAX];
    if (!echo_aead_decrypt(derived, buf, ECHO_HEADER_LEN, ct, ct_len, plaintext))
        return ECHO_ERR_AUTH_FAILED;

    size_t pt_len = ct_len - 16;
    if (pt_len < 32) return ECHO_ERR_BAD_PAYLOAD_LEN;
    memcpy(out->cluster_key, plaintext, 32);
    size_t init_len = pt_len - 32;
    if (init_len > ECHO_BOOTSTRAP_INIT_PAYLOAD_MAX) return ECHO_ERR_BAD_PAYLOAD_LEN;
    out->init_payload_len = init_len;
    if (init_len) memcpy(out->init_payload, plaintext + 32, init_len);
    return ECHO_OK;
}

// ─── BOOTSTRAP_ACK 0x21 ────────────────────────────────────────────────────

echo_err_t echo_encode_bootstrap_ack(uint8_t *out, size_t out_cap, size_t *out_len,
                                      const uint8_t sender_id[8],
                                      uint64_t seq, int64_t ts_ms,
                                      uint8_t status, uint64_t witness_uptime_ms,
                                      const uint8_t *cluster_key) {
    if (status != 0 && status != 1) return ECHO_ERR_BAD_FIELD;
    size_t pl = 9;
    size_t total = ECHO_HEADER_LEN + pl + 32;
    if (out_cap < total) return ECHO_ERR_BAD_LENGTH;
    echo_header_t h = {
        .msg_type = ECHO_MSG_BOOTSTRAP_ACK, .flags = 0,
        .sequence = seq, .timestamp_ms = ts_ms,
        .payload_len = (uint16_t)pl,
    };
    memcpy(h.sender_id, sender_id, 8);
    echo_header_pack(out, &h);
    out[ECHO_HEADER_LEN] = status;
    w_u64(out + ECHO_HEADER_LEN + 1, witness_uptime_ms);
    finalize_hmac(out, ECHO_HEADER_LEN + pl, cluster_key);
    *out_len = total;
    return ECHO_OK;
}
