// Wire-format encode/decode for Bedrock Echo v1.

#include "echo.h"
#include <string.h>

// ─── Internal helpers ───────────────────────────────────────────────────────

static inline void wr_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF; p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8)  & 0xFF; p[3] =  v        & 0xFF;
}

static inline void wr_i64_be(uint8_t *p, int64_t v) {
    uint64_t u = (uint64_t)v;
    p[0] = (u >> 56) & 0xFF; p[1] = (u >> 48) & 0xFF;
    p[2] = (u >> 40) & 0xFF; p[3] = (u >> 32) & 0xFF;
    p[4] = (u >> 24) & 0xFF; p[5] = (u >> 16) & 0xFF;
    p[6] = (u >> 8)  & 0xFF; p[7] =  u        & 0xFF;
}

static inline int64_t rd_i64_be(const uint8_t *p) {
    uint64_t u = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
                 ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
                 ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
                 ((uint64_t)p[6] << 8)  |  (uint64_t)p[7];
    return (int64_t)u;
}

static bool is_known_msg_type(uint8_t t) {
    switch (t) {
        case ECHO_MSG_HEARTBEAT:
        case ECHO_MSG_STATUS_LIST:
        case ECHO_MSG_STATUS_DETAIL:
        case ECHO_MSG_DISCOVER:
        case ECHO_MSG_INIT:
        case ECHO_MSG_BOOTSTRAP:
        case ECHO_MSG_BOOTSTRAP_ACK:
            return true;
        default:
            return false;
    }
}

// ─── Header ─────────────────────────────────────────────────────────────────

echo_err_t echo_header_pack(uint8_t out[ECHO_HEADER_LEN], const echo_header_t *hdr) {
    memcpy(out, ECHO_MAGIC, 4);
    out[4] = hdr->msg_type;
    out[5] = hdr->sender_id;
    wr_i64_be(out + 6, hdr->timestamp_ms);
    return ECHO_OK;
}

echo_err_t echo_header_unpack(echo_header_t *out, const uint8_t *buf, size_t len) {
    if (len < ECHO_HEADER_LEN) return ECHO_ERR_TOO_SHORT;
    if (memcmp(buf, ECHO_MAGIC, 4) != 0) return ECHO_ERR_BAD_MAGIC;
    if (!is_known_msg_type(buf[4])) return ECHO_ERR_BAD_MSG_TYPE;
    out->msg_type = buf[4];
    out->sender_id = buf[5];
    out->timestamp_ms = rd_i64_be(buf + 6);
    return ECHO_OK;
}

void echo_derive_nonce(uint8_t out[ECHO_AEAD_NONCE_LEN],
                        uint8_t sender_id, int64_t timestamp_ms) {
    out[0] = sender_id;
    out[1] = 0; out[2] = 0; out[3] = 0;
    wr_i64_be(out + 4, timestamp_ms);
}

// ─── HEARTBEAT (0x01) ───────────────────────────────────────────────────────

echo_err_t echo_encode_heartbeat(uint8_t *out, size_t out_cap, size_t *out_len,
                                  uint8_t sender_id, int64_t timestamp_ms,
                                  uint8_t query_target_id,
                                  const uint8_t *own_payload, size_t own_payload_len,
                                  const uint8_t cluster_key[32]) {
    if (sender_id > ECHO_NODE_SENDER_ID_MAX) return ECHO_ERR_BAD_SENDER_ID;
    if (own_payload_len % ECHO_PAYLOAD_BLOCK_SIZE != 0) return ECHO_ERR_BAD_PAYLOAD_SIZE;
    if (own_payload_len > ECHO_PAYLOAD_MAX_BYTES) return ECHO_ERR_BAD_PAYLOAD_SIZE;
    size_t n_blocks = own_payload_len / ECHO_PAYLOAD_BLOCK_SIZE;
    size_t pt_len = 2 + own_payload_len;
    size_t total = ECHO_HEADER_LEN + pt_len + ECHO_AEAD_TAG_LEN;
    if (total > ECHO_MTU_CAP) return ECHO_ERR_OVER_MTU;
    if (out_cap < total) return ECHO_ERR_BAD_LENGTH;

    echo_header_t hdr = { .msg_type = ECHO_MSG_HEARTBEAT,
                          .sender_id = sender_id,
                          .timestamp_ms = timestamp_ms };
    echo_header_pack(out, &hdr);

    uint8_t pt[2 + ECHO_PAYLOAD_MAX_BYTES];
    pt[0] = query_target_id;
    pt[1] = (uint8_t)n_blocks;
    if (own_payload_len) memcpy(pt + 2, own_payload, own_payload_len);

    uint8_t nonce[ECHO_AEAD_NONCE_LEN];
    echo_derive_nonce(nonce, sender_id, timestamp_ms);
    if (!echo_aead_encrypt(cluster_key, nonce, out, ECHO_HEADER_LEN,
                           pt, pt_len, out + ECHO_HEADER_LEN)) {
        return ECHO_ERR_AUTH_FAILED;
    }
    *out_len = total;
    return ECHO_OK;
}

echo_err_t echo_decode_heartbeat(const uint8_t *buf, size_t buf_len,
                                  const uint8_t cluster_key[32],
                                  echo_header_t *out_header,
                                  uint8_t *out_query_target_id,
                                  uint8_t *pt_scratch, size_t pt_scratch_cap,
                                  const uint8_t **out_own_payload,
                                  size_t *out_own_payload_len) {
    if (buf_len < ECHO_HEADER_LEN + 2 + ECHO_AEAD_TAG_LEN) return ECHO_ERR_TOO_SHORT;
    echo_err_t e = echo_header_unpack(out_header, buf, buf_len);
    if (e != ECHO_OK) return e;
    if (out_header->msg_type != ECHO_MSG_HEARTBEAT) return ECHO_ERR_BAD_MSG_TYPE;

    uint8_t nonce[ECHO_AEAD_NONCE_LEN];
    echo_derive_nonce(nonce, out_header->sender_id, out_header->timestamp_ms);

    size_t ct_len = buf_len - ECHO_HEADER_LEN;
    size_t pt_len = ct_len - ECHO_AEAD_TAG_LEN;
    if (pt_len > pt_scratch_cap) return ECHO_ERR_BAD_LENGTH;
    if (!echo_aead_decrypt(cluster_key, nonce, buf, ECHO_HEADER_LEN,
                           buf + ECHO_HEADER_LEN, ct_len, pt_scratch)) {
        return ECHO_ERR_AUTH_FAILED;
    }

    if (pt_len < 2) return ECHO_ERR_BAD_LENGTH;
    *out_query_target_id = pt_scratch[0];
    uint8_t n_blocks = pt_scratch[1];
    if (n_blocks > ECHO_PAYLOAD_MAX_BLOCKS) return ECHO_ERR_BAD_FIELD;
    size_t expected_pt = 2 + (size_t)n_blocks * ECHO_PAYLOAD_BLOCK_SIZE;
    if (pt_len != expected_pt) return ECHO_ERR_BAD_LENGTH;
    *out_own_payload = pt_scratch + 2;
    *out_own_payload_len = (size_t)n_blocks * ECHO_PAYLOAD_BLOCK_SIZE;
    return ECHO_OK;
}

// ─── STATUS_LIST (0x02) ─────────────────────────────────────────────────────

echo_err_t echo_encode_status_list(uint8_t *out, size_t out_cap, size_t *out_len,
                                    int64_t timestamp_ms,
                                    uint32_t witness_uptime_seconds,
                                    const echo_list_entry_t *entries, size_t num_entries,
                                    const uint8_t cluster_key[32]) {
    if (num_entries > ECHO_LIST_MAX_ENTRIES) return ECHO_ERR_BAD_FIELD;
    size_t pt_len = 5 + num_entries * ECHO_LIST_ENTRY_LEN;
    size_t total = ECHO_HEADER_LEN + pt_len + ECHO_AEAD_TAG_LEN;
    if (total > ECHO_MTU_CAP) return ECHO_ERR_OVER_MTU;
    if (out_cap < total) return ECHO_ERR_BAD_LENGTH;

    echo_header_t hdr = { .msg_type = ECHO_MSG_STATUS_LIST,
                          .sender_id = ECHO_WITNESS_SENDER_ID,
                          .timestamp_ms = timestamp_ms };
    echo_header_pack(out, &hdr);

    uint8_t pt[5 + ECHO_LIST_MAX_ENTRIES * ECHO_LIST_ENTRY_LEN];
    wr_u32_be(pt, witness_uptime_seconds);
    pt[4] = (uint8_t)num_entries;
    size_t off = 5;
    for (size_t i = 0; i < num_entries; ++i) {
        pt[off] = entries[i].peer_sender_id;
        wr_u32_be(pt + off + 1, entries[i].last_seen_ms);
        off += ECHO_LIST_ENTRY_LEN;
    }

    uint8_t nonce[ECHO_AEAD_NONCE_LEN];
    echo_derive_nonce(nonce, ECHO_WITNESS_SENDER_ID, timestamp_ms);
    if (!echo_aead_encrypt(cluster_key, nonce, out, ECHO_HEADER_LEN,
                           pt, pt_len, out + ECHO_HEADER_LEN)) {
        return ECHO_ERR_AUTH_FAILED;
    }
    *out_len = total;
    return ECHO_OK;
}

// ─── STATUS_DETAIL (0x03) ───────────────────────────────────────────────────

echo_err_t echo_encode_status_detail_found(uint8_t *out, size_t out_cap, size_t *out_len,
                                            int64_t timestamp_ms,
                                            uint32_t witness_uptime_seconds,
                                            uint8_t target_sender_id,
                                            const uint8_t peer_ipv4[4],
                                            uint32_t peer_seen_ms_ago,
                                            const uint8_t *peer_payload, size_t peer_payload_len,
                                            const uint8_t cluster_key[32]) {
    if (peer_payload_len % ECHO_PAYLOAD_BLOCK_SIZE != 0) return ECHO_ERR_BAD_PAYLOAD_SIZE;
    if (peer_payload_len > ECHO_PAYLOAD_MAX_BYTES) return ECHO_ERR_BAD_PAYLOAD_SIZE;
    size_t n_blocks = peer_payload_len / ECHO_PAYLOAD_BLOCK_SIZE;
    size_t pt_len = 6 + 4 + 4 + peer_payload_len;
    size_t total = ECHO_HEADER_LEN + pt_len + ECHO_AEAD_TAG_LEN;
    if (total > ECHO_MTU_CAP) return ECHO_ERR_OVER_MTU;
    if (out_cap < total) return ECHO_ERR_BAD_LENGTH;

    echo_header_t hdr = { .msg_type = ECHO_MSG_STATUS_DETAIL,
                          .sender_id = ECHO_WITNESS_SENDER_ID,
                          .timestamp_ms = timestamp_ms };
    echo_header_pack(out, &hdr);

    uint8_t pt[6 + 4 + 4 + ECHO_PAYLOAD_MAX_BYTES];
    wr_u32_be(pt, witness_uptime_seconds);
    pt[4] = target_sender_id;
    pt[5] = (uint8_t)n_blocks;
    memcpy(pt + 6, peer_ipv4, 4);
    wr_u32_be(pt + 10, peer_seen_ms_ago);
    if (peer_payload_len) memcpy(pt + 14, peer_payload, peer_payload_len);

    uint8_t nonce[ECHO_AEAD_NONCE_LEN];
    echo_derive_nonce(nonce, ECHO_WITNESS_SENDER_ID, timestamp_ms);
    if (!echo_aead_encrypt(cluster_key, nonce, out, ECHO_HEADER_LEN,
                           pt, pt_len, out + ECHO_HEADER_LEN)) {
        return ECHO_ERR_AUTH_FAILED;
    }
    *out_len = total;
    return ECHO_OK;
}

echo_err_t echo_encode_status_detail_not_found(uint8_t *out, size_t out_cap, size_t *out_len,
                                                int64_t timestamp_ms,
                                                uint32_t witness_uptime_seconds,
                                                uint8_t target_sender_id,
                                                const uint8_t cluster_key[32]) {
    size_t pt_len = 6;
    size_t total = ECHO_HEADER_LEN + pt_len + ECHO_AEAD_TAG_LEN;
    if (out_cap < total) return ECHO_ERR_BAD_LENGTH;

    echo_header_t hdr = { .msg_type = ECHO_MSG_STATUS_DETAIL,
                          .sender_id = ECHO_WITNESS_SENDER_ID,
                          .timestamp_ms = timestamp_ms };
    echo_header_pack(out, &hdr);

    uint8_t pt[6];
    wr_u32_be(pt, witness_uptime_seconds);
    pt[4] = target_sender_id;
    pt[5] = ECHO_STATUS_DETAIL_NOT_FOUND_BIT;

    uint8_t nonce[ECHO_AEAD_NONCE_LEN];
    echo_derive_nonce(nonce, ECHO_WITNESS_SENDER_ID, timestamp_ms);
    if (!echo_aead_encrypt(cluster_key, nonce, out, ECHO_HEADER_LEN,
                           pt, pt_len, out + ECHO_HEADER_LEN)) {
        return ECHO_ERR_AUTH_FAILED;
    }
    *out_len = total;
    return ECHO_OK;
}

// ─── DISCOVER (0x04) — zero-padded to 62 B for anti-amplification ─────────

echo_err_t echo_encode_discover(uint8_t *out, size_t out_cap, size_t *out_len,
                                 uint8_t sender_id, int64_t timestamp_ms) {
    if (sender_id > ECHO_NODE_SENDER_ID_MAX) return ECHO_ERR_BAD_SENDER_ID;
    if (out_cap < ECHO_DISCOVER_LEN) return ECHO_ERR_BAD_LENGTH;
    echo_header_t hdr = { .msg_type = ECHO_MSG_DISCOVER,
                          .sender_id = sender_id,
                          .timestamp_ms = timestamp_ms };
    echo_header_pack(out, &hdr);
    // Bytes 14..62: MUST be zero on send (PROTOCOL.md §5.4).
    memset(out + ECHO_HEADER_LEN, 0, ECHO_DISCOVER_PAD_LEN);
    *out_len = ECHO_DISCOVER_LEN;
    return ECHO_OK;
}

echo_err_t echo_decode_discover(const uint8_t *buf, size_t buf_len,
                                 echo_header_t *out_header) {
    if (buf_len != ECHO_DISCOVER_LEN) return ECHO_ERR_BAD_LENGTH;
    echo_err_t e = echo_header_unpack(out_header, buf, buf_len);
    if (e != ECHO_OK) return e;
    if (out_header->msg_type != ECHO_MSG_DISCOVER) return ECHO_ERR_BAD_MSG_TYPE;
    if (out_header->sender_id > ECHO_NODE_SENDER_ID_MAX) return ECHO_ERR_BAD_SENDER_ID;
    // Padding bytes are MAY-check; we don't enforce zero-only so future
    // forward-compat use of those bytes via msg_type extension stays open.
    return ECHO_OK;
}

// ─── INIT (0x10) — witness reply, carries pubkey + 16 B cookie ────────────

echo_err_t echo_encode_init(uint8_t *out, size_t out_cap, size_t *out_len,
                             int64_t timestamp_ms,
                             const uint8_t witness_pubkey[32],
                             const uint8_t cookie[ECHO_COOKIE_LEN]) {
    if (out_cap < ECHO_INIT_LEN) return ECHO_ERR_BAD_LENGTH;
    echo_header_t hdr = { .msg_type = ECHO_MSG_INIT,
                          .sender_id = ECHO_WITNESS_SENDER_ID,
                          .timestamp_ms = timestamp_ms };
    echo_header_pack(out, &hdr);
    memcpy(out + ECHO_HEADER_LEN, witness_pubkey, 32);
    memcpy(out + ECHO_HEADER_LEN + 32, cookie, ECHO_COOKIE_LEN);
    *out_len = ECHO_INIT_LEN;
    return ECHO_OK;
}

// ─── BOOTSTRAP (0x20) — AAD = header || cookie (30 bytes) ────────────────

echo_err_t echo_encode_bootstrap(uint8_t *out, size_t out_cap, size_t *out_len,
                                  uint8_t sender_id, int64_t timestamp_ms,
                                  const uint8_t cluster_key[32],
                                  const uint8_t witness_pubkey[32],
                                  const uint8_t eph_priv[32],
                                  const uint8_t cookie[ECHO_COOKIE_LEN]) {
    if (sender_id > ECHO_NODE_SENDER_ID_MAX) return ECHO_ERR_BAD_SENDER_ID;
    if (out_cap < ECHO_BOOTSTRAP_LEN) return ECHO_ERR_BAD_LENGTH;
    uint8_t eph_pub[32];
    if (!echo_x25519_pub_from_priv(eph_priv, eph_pub)) return ECHO_ERR_AUTH_FAILED;
    uint8_t shared[32];
    if (!echo_x25519_shared(eph_priv, witness_pubkey, shared)) return ECHO_ERR_AUTH_FAILED;
    uint8_t aead_key[32];
    if (!echo_hkdf_sha256(shared, 32, aead_key)) return ECHO_ERR_AUTH_FAILED;

    echo_header_t hdr = { .msg_type = ECHO_MSG_BOOTSTRAP,
                          .sender_id = sender_id,
                          .timestamp_ms = timestamp_ms };
    echo_header_pack(out, &hdr);
    memcpy(out + ECHO_HEADER_LEN, cookie, ECHO_COOKIE_LEN);
    const size_t aad_len = ECHO_HEADER_LEN + ECHO_COOKIE_LEN;        // 30
    const size_t eph_off = aad_len;                                   // 30
    const size_t ct_off  = eph_off + 32;                              // 62
    memcpy(out + eph_off, eph_pub, 32);

    uint8_t nonce[ECHO_AEAD_NONCE_LEN] = {0};
    if (!echo_aead_encrypt(aead_key, nonce, out, aad_len,
                           cluster_key, 32, out + ct_off)) {
        return ECHO_ERR_AUTH_FAILED;
    }
    *out_len = ECHO_BOOTSTRAP_LEN;
    return ECHO_OK;
}

echo_err_t echo_decode_bootstrap(const uint8_t *buf, size_t buf_len,
                                  const uint8_t witness_priv[32],
                                  echo_header_t *out_header,
                                  uint8_t out_cookie[ECHO_COOKIE_LEN],
                                  uint8_t out_cluster_key[32]) {
    if (buf_len != ECHO_BOOTSTRAP_LEN) return ECHO_ERR_BAD_LENGTH;
    echo_err_t e = echo_header_unpack(out_header, buf, buf_len);
    if (e != ECHO_OK) return e;
    if (out_header->msg_type != ECHO_MSG_BOOTSTRAP) return ECHO_ERR_BAD_MSG_TYPE;
    if (out_header->sender_id > ECHO_NODE_SENDER_ID_MAX) return ECHO_ERR_BAD_SENDER_ID;

    memcpy(out_cookie, buf + ECHO_HEADER_LEN, ECHO_COOKIE_LEN);
    const size_t aad_len = ECHO_HEADER_LEN + ECHO_COOKIE_LEN;
    const size_t eph_off = aad_len;
    const size_t ct_off  = eph_off + 32;

    const uint8_t *eph_pub = buf + eph_off;
    uint8_t shared[32];
    if (!echo_x25519_shared(witness_priv, eph_pub, shared)) return ECHO_ERR_AUTH_FAILED;
    uint8_t aead_key[32];
    if (!echo_hkdf_sha256(shared, 32, aead_key)) return ECHO_ERR_AUTH_FAILED;

    uint8_t nonce[ECHO_AEAD_NONCE_LEN] = {0};
    if (!echo_aead_decrypt(aead_key, nonce, buf, aad_len,
                           buf + ct_off, 32 + ECHO_AEAD_TAG_LEN,
                           out_cluster_key)) {
        return ECHO_ERR_AUTH_FAILED;
    }
    return ECHO_OK;
}

// ─── BOOTSTRAP_ACK (0x21) ───────────────────────────────────────────────────

echo_err_t echo_encode_bootstrap_ack(uint8_t *out, size_t out_cap, size_t *out_len,
                                      int64_t timestamp_ms, uint8_t status,
                                      uint32_t witness_uptime_seconds,
                                      const uint8_t cluster_key[32]) {
    if (out_cap < ECHO_BOOTSTRAP_ACK_LEN) return ECHO_ERR_BAD_LENGTH;
    echo_header_t hdr = { .msg_type = ECHO_MSG_BOOTSTRAP_ACK,
                          .sender_id = ECHO_WITNESS_SENDER_ID,
                          .timestamp_ms = timestamp_ms };
    echo_header_pack(out, &hdr);

    uint8_t pt[ECHO_BOOTSTRAP_ACK_PT_LEN];
    pt[0] = status;
    wr_u32_be(pt + 1, witness_uptime_seconds);

    uint8_t nonce[ECHO_AEAD_NONCE_LEN];
    echo_derive_nonce(nonce, ECHO_WITNESS_SENDER_ID, timestamp_ms);
    if (!echo_aead_encrypt(cluster_key, nonce, out, ECHO_HEADER_LEN,
                           pt, ECHO_BOOTSTRAP_ACK_PT_LEN, out + ECHO_HEADER_LEN)) {
        return ECHO_ERR_AUTH_FAILED;
    }
    *out_len = ECHO_BOOTSTRAP_ACK_LEN;
    return ECHO_OK;
}
