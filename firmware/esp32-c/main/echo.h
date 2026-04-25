// Bedrock Echo v1 — protocol types + constants for the ESP32 C impl.
// See PROTOCOL.md for the authoritative wire format and
// docs/witness-implementation.md for witness-side behavior.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ─── Wire constants (PROTOCOL.md §2, §3) ─────────────────────────────────────
#define ECHO_MAGIC "Echo"
#define ECHO_HEADER_LEN 14u
#define ECHO_AEAD_TAG_LEN 16u
#define ECHO_AEAD_NONCE_LEN 12u
#define ECHO_MTU_CAP 1400u

#define ECHO_MSG_HEARTBEAT      0x01u
#define ECHO_MSG_STATUS_LIST    0x02u
#define ECHO_MSG_STATUS_DETAIL  0x03u
#define ECHO_MSG_DISCOVER       0x04u
#define ECHO_MSG_INIT           0x10u
#define ECHO_MSG_BOOTSTRAP      0x20u
#define ECHO_MSG_BOOTSTRAP_ACK  0x21u

// sender_id reservations
#define ECHO_WITNESS_SENDER_ID 0xFFu
#define ECHO_NODE_SENDER_ID_MAX 0xFEu

// Block-granular payloads (PROTOCOL.md §4.1)
#define ECHO_PAYLOAD_BLOCK_SIZE 32u
#define ECHO_PAYLOAD_MAX_BLOCKS 36u
#define ECHO_PAYLOAD_MAX_BYTES (ECHO_PAYLOAD_BLOCK_SIZE * ECHO_PAYLOAD_MAX_BLOCKS) // 1152

// STATUS_LIST entry constraints
#define ECHO_LIST_ENTRY_LEN 5u
#define ECHO_LIST_MAX_ENTRIES 128u

// query_target_id sentinel meaning "give me LIST not DETAIL"
#define ECHO_QUERY_LIST_SENTINEL 0xFFu

// Crypto field sizes
#define ECHO_CLUSTER_KEY_LEN 32u
#define ECHO_EPH_PUBKEY_LEN 32u
#define ECHO_WITNESS_PUBKEY_LEN 32u

// Anti-spoof cookie (PROTOCOL.md §11.2)
#define ECHO_COOKIE_LEN 16u
#define ECHO_WITNESS_COOKIE_SECRET_LEN 32u
#define ECHO_COOKIE_ROTATION_MS (3600u * 1000u)  // 1 hour

// DISCOVER zero-padding (anti-amp; PROTOCOL.md §1 principle 13, §5.4)
#define ECHO_DISCOVER_PAD_LEN 48u

// Total fixed-size packets
#define ECHO_DISCOVER_LEN (ECHO_HEADER_LEN + ECHO_DISCOVER_PAD_LEN)  // 62
#define ECHO_INIT_LEN (ECHO_HEADER_LEN + ECHO_WITNESS_PUBKEY_LEN + ECHO_COOKIE_LEN)  // 62
#define ECHO_BOOTSTRAP_LEN \
    (ECHO_HEADER_LEN + ECHO_COOKIE_LEN + ECHO_EPH_PUBKEY_LEN + ECHO_CLUSTER_KEY_LEN + ECHO_AEAD_TAG_LEN)  // 110
#define ECHO_BOOTSTRAP_ACK_PT_LEN 5u
#define ECHO_BOOTSTRAP_ACK_LEN \
    (ECHO_HEADER_LEN + ECHO_BOOTSTRAP_ACK_PT_LEN + ECHO_AEAD_TAG_LEN)  // 35

// STATUS_DETAIL status_and_blocks byte
#define ECHO_STATUS_DETAIL_NOT_FOUND_BIT 0x80u
#define ECHO_STATUS_DETAIL_BLOCKS_MASK   0x3Fu

// HKDF info string (must match other impls byte-for-byte)
static const uint8_t ECHO_HKDF_INFO[] = "bedrock-echo bootstrap";
#define ECHO_HKDF_INFO_LEN (sizeof(ECHO_HKDF_INFO) - 1u)

// ─── Witness state sizing (Big profile for Olimex ESP32-POE-ISO) ────────────
//
//   static state budget (approximate):
//     256 nodes    × ~24 B  = ~6 KB    (metadata only — payloads in pool)
//     128 clusters × ~64 B  = ~8 KB
//     192 rate bkt × ~28 B  = ~5 KB
//     payload pool          = 64 KB    (2048 blocks × 32 B)
//                              ──────
//                              ~83 KB .bss on libmain
//
// ESP32 classic has 180 KB DRAM; ESP-IDF baseline uses ~12 KB .bss + .data.
// Heap remaining for LwIP/FreeRTOS/mbedTLS: ~85 KB. Comfortable.
#define ECHO_MAX_NODES        256u
#define ECHO_MAX_CLUSTERS     128u
#define ECHO_MAX_TRACKED_IPS  192u

#define ECHO_POOL_BLOCKS      2048u
#define ECHO_POOL_BYTES       (ECHO_POOL_BLOCKS * ECHO_PAYLOAD_BLOCK_SIZE)  // 64 KB

// Per-cluster offset adaptation (PROTOCOL.md §6.2)
#define ECHO_MAX_BACKWARD_JUMP_MS 1000
#define ECHO_MAX_BACKWARD_STEP_MS 10

#define ECHO_UDP_PORT_DEFAULT 12321u

// Rate limit (PROTOCOL.md §11)
#define ECHO_RL_RATE_PER_SEC      10.0f
#define ECHO_RL_BURST             20.0f
#define ECHO_RL_UNKNOWN_INTERVAL_MS 1000

// ─── Errors ──────────────────────────────────────────────────────────────────
typedef enum {
    ECHO_OK = 0,
    ECHO_ERR_TOO_SHORT,
    ECHO_ERR_BAD_LENGTH,
    ECHO_ERR_BAD_MAGIC,
    ECHO_ERR_BAD_MSG_TYPE,
    ECHO_ERR_BAD_SENDER_ID,
    ECHO_ERR_BAD_FIELD,
    ECHO_ERR_AUTH_FAILED,
    ECHO_ERR_OVER_MTU,
    ECHO_ERR_BAD_PAYLOAD_SIZE,
} echo_err_t;

// ─── Header (14 bytes) ──────────────────────────────────────────────────────
typedef struct {
    uint8_t msg_type;
    uint8_t sender_id;        // 0x00..0xFE for nodes, 0xFF for witness
    int64_t timestamp_ms;
} echo_header_t;

echo_err_t echo_header_pack(uint8_t out[ECHO_HEADER_LEN], const echo_header_t *hdr);
echo_err_t echo_header_unpack(echo_header_t *out, const uint8_t *buf, size_t len);

// 12-byte AEAD nonce derivation: sender_id || 0x000000 || timestamp_ms (BE)
void echo_derive_nonce(uint8_t out[ECHO_AEAD_NONCE_LEN],
                        uint8_t sender_id, int64_t timestamp_ms);

// ─── Crypto wrappers (mbedTLS + TweetNaCl) ───────────────────────────────────
bool echo_x25519_generate(uint8_t priv_out[32], uint8_t pub_out[32]);
bool echo_x25519_pub_from_priv(const uint8_t priv[32], uint8_t pub_out[32]);
bool echo_x25519_shared(const uint8_t priv[32], const uint8_t peer_pub[32],
                        uint8_t shared_out[32]);

bool echo_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, uint8_t out[32]);

// Anti-spoof cookie (PROTOCOL.md §11.2):
//     cookie = SHA-256(witness_cookie_secret || src_ip_be)[:16]
void echo_derive_cookie(const uint8_t witness_cookie_secret[32],
                        const uint8_t src_ip_be[4],
                        uint8_t out[ECHO_COOKIE_LEN]);

// ChaCha20-Poly1305. encrypt: writes ct||tag (pt_len + 16 bytes) into out.
bool echo_aead_encrypt(const uint8_t key[32],
                       const uint8_t nonce[ECHO_AEAD_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *out);
// decrypt: input is ct||tag of length ct_len; writes pt of length ct_len - 16.
bool echo_aead_decrypt(const uint8_t key[32],
                       const uint8_t nonce[ECHO_AEAD_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *out);

// ─── State tables (RAM-only) ─────────────────────────────────────────────────
typedef struct {
    bool in_use;
    uint8_t cluster_key[ECHO_CLUSTER_KEY_LEN];
    uint64_t bootstrapped_ms;
    uint8_t num_nodes;
    int64_t cluster_offset;        // cluster_now_ms = uptime_ms + cluster_offset
    int64_t last_tx_timestamp;     // strict-monotonic outgoing ts in cluster frame
} echo_cluster_entry_t;

typedef struct {
    bool in_use;
    uint8_t sender_id;             // 1 byte (was [u8;8])
    uint8_t sender_ipv4[4];
    uint16_t sender_src_port;
    uint16_t cluster_slot;
    uint64_t last_rx_ms;
    int64_t last_rx_timestamp;     // anti-replay + AEAD nonce-uniqueness invariant
    uint16_t payload_first_block;  // index into pool
    uint8_t payload_n_blocks;      // 0..36
} echo_node_entry_t;

typedef struct {
    bool in_use;
    uint8_t ipv4[4];
    float tokens;
    uint64_t last_refill_ms;
    uint64_t last_unknown_ms;
} echo_rate_entry_t;

typedef struct echo_state_s {
    uint8_t witness_priv[32];
    uint8_t witness_pub[32];
    uint64_t start_ms;
    echo_cluster_entry_t clusters[ECHO_MAX_CLUSTERS];
    echo_node_entry_t nodes[ECHO_MAX_NODES];
    echo_rate_entry_t rate_limits[ECHO_MAX_TRACKED_IPS];
    uint8_t pool[ECHO_POOL_BYTES];
    // Anti-spoof cookie state (PROTOCOL.md §11.2). Witness rotates the
    // current secret hourly; both current and previous are valid for
    // incoming BOOTSTRAPs.
    uint8_t cookie_current[ECHO_WITNESS_COOKIE_SECRET_LEN];
    uint8_t cookie_previous[ECHO_WITNESS_COOKIE_SECRET_LEN];
    uint64_t last_cookie_rotation_ms;
} echo_state_t;

void echo_state_init(echo_state_t *state, const uint8_t priv[32], uint64_t now_ms);

// Cookie state — caller supplies fresh randomness for the secret(s).
// In production `echo_state_init` populates these via the platform RNG;
// this entry point allows tests / repro to use deterministic secrets.
void echo_state_init_with_cookies(echo_state_t *state,
                                   const uint8_t priv[32],
                                   uint64_t now_ms,
                                   const uint8_t cookie_current[32],
                                   const uint8_t cookie_previous[32]);

// Lazy hourly rotation. Call frequently; `new_secret` is consumed only
// when a rotation actually happens (≥ 1h since the last).
bool echo_state_cookie_rotation_due(const echo_state_t *state, uint64_t now_ms);
void echo_state_maybe_rotate_cookie(echo_state_t *state, uint64_t now_ms,
                                    const uint8_t new_secret[32]);

// Compute the cookie a node at src_ip should echo on its next BOOTSTRAP.
void echo_state_cookie_for(const echo_state_t *state,
                            const uint8_t src_ip[4],
                            uint8_t out[ECHO_COOKIE_LEN]);
// Validate `cookie` against current OR previous secret.
bool echo_state_cookie_valid(const echo_state_t *state,
                              const uint8_t src_ip[4],
                              const uint8_t cookie[ECHO_COOKIE_LEN]);

uint64_t echo_state_uptime_ms(const echo_state_t *state, uint64_t now_ms);
void echo_state_age_out(echo_state_t *state, uint64_t now_ms);
bool echo_state_allow(echo_state_t *state, const uint8_t ipv4[4], uint64_t now_ms);
bool echo_state_allow_unknown(echo_state_t *state, const uint8_t ipv4[4], uint64_t now_ms);

// Apply asymmetric per-cluster offset adaptation. Returns false if the
// packet is too far behind cluster frame (caller should silent-drop).
bool echo_state_adapt_offset(echo_state_t *state, uint16_t cluster_slot,
                              int64_t pkt_ts, uint64_t uptime_ms);

// Compute next outgoing timestamp_ms in cluster's frame (strict-monotonic).
int64_t echo_state_next_tx_ts(echo_state_t *state, uint16_t cluster_slot,
                               uint64_t uptime_ms);

int echo_state_find_cluster_by_key(const echo_state_t *state, const uint8_t key[32]);
// Find first cluster slot that's free; -1 if full.
int echo_state_alloc_cluster_slot(const echo_state_t *state);
// Find first node slot that's free; -1 if full.
int echo_state_alloc_node_slot(const echo_state_t *state);

// ─── Block allocator (PROTOCOL.md / witness-implementation.md §3) ───────────
// Pool of 32-byte blocks; node table is the allocation map (no bitmap).
// `alloc` returns the start block index for N consecutive free blocks (or -1).
// `defrag` packs all in-use allocations toward the low end of the pool.

int16_t echo_pool_alloc(echo_state_t *state, uint16_t n_blocks);
void   echo_pool_free(echo_state_t *state, uint16_t first, uint16_t n);
void   echo_pool_defrag(echo_state_t *state);
size_t echo_pool_blocks_in_use(const echo_state_t *state);

// ─── Wire encode / decode helpers (PROTOCOL.md §5) ──────────────────────────
//
// HEARTBEAT
//   own_payload_len must be a multiple of 32, max 1152. Returns total bytes
//   written to `out`.
echo_err_t echo_encode_heartbeat(uint8_t *out, size_t out_cap, size_t *out_len,
                                  uint8_t sender_id, int64_t timestamp_ms,
                                  uint8_t query_target_id,
                                  const uint8_t *own_payload, size_t own_payload_len,
                                  const uint8_t cluster_key[32]);
//   Decoder verifies AEAD in place. On success: writes plaintext into a
//   caller-supplied scratch buffer pt[], sets *qt and points
//   *own_payload to pt + 2 with *own_payload_len_out = N×32.
echo_err_t echo_decode_heartbeat(const uint8_t *buf, size_t buf_len,
                                  const uint8_t cluster_key[32],
                                  echo_header_t *out_header,
                                  uint8_t *out_query_target_id,
                                  uint8_t *pt_scratch, size_t pt_scratch_cap,
                                  const uint8_t **out_own_payload,
                                  size_t *out_own_payload_len);

// STATUS_LIST entry (5 bytes on the wire)
typedef struct {
    uint8_t peer_sender_id;
    uint32_t last_seen_ms;
} echo_list_entry_t;

echo_err_t echo_encode_status_list(uint8_t *out, size_t out_cap, size_t *out_len,
                                    int64_t timestamp_ms,
                                    uint32_t witness_uptime_seconds,
                                    const echo_list_entry_t *entries, size_t num_entries,
                                    const uint8_t cluster_key[32]);

// STATUS_DETAIL
echo_err_t echo_encode_status_detail_found(uint8_t *out, size_t out_cap, size_t *out_len,
                                            int64_t timestamp_ms,
                                            uint32_t witness_uptime_seconds,
                                            uint8_t target_sender_id,
                                            const uint8_t peer_ipv4[4],
                                            uint32_t peer_seen_ms_ago,
                                            const uint8_t *peer_payload, size_t peer_payload_len,
                                            const uint8_t cluster_key[32]);
echo_err_t echo_encode_status_detail_not_found(uint8_t *out, size_t out_cap, size_t *out_len,
                                                int64_t timestamp_ms,
                                                uint32_t witness_uptime_seconds,
                                                uint8_t target_sender_id,
                                                const uint8_t cluster_key[32]);

// DISCOVER
echo_err_t echo_encode_discover(uint8_t *out, size_t out_cap, size_t *out_len,
                                 uint8_t sender_id, int64_t timestamp_ms);
echo_err_t echo_decode_discover(const uint8_t *buf, size_t buf_len,
                                 echo_header_t *out_header);

// INIT (renamed from UNKNOWN_SOURCE in v1 polish; carries cookie)
echo_err_t echo_encode_init(uint8_t *out, size_t out_cap, size_t *out_len,
                             int64_t timestamp_ms,
                             const uint8_t witness_pubkey[32],
                             const uint8_t cookie[ECHO_COOKIE_LEN]);

// BOOTSTRAP — carries 16 B cookie in AAD (PROTOCOL.md §5.6).
echo_err_t echo_encode_bootstrap(uint8_t *out, size_t out_cap, size_t *out_len,
                                  uint8_t sender_id, int64_t timestamp_ms,
                                  const uint8_t cluster_key[32],
                                  const uint8_t witness_pubkey[32],
                                  const uint8_t eph_priv[32],
                                  const uint8_t cookie[ECHO_COOKIE_LEN]);
echo_err_t echo_decode_bootstrap(const uint8_t *buf, size_t buf_len,
                                  const uint8_t witness_priv[32],
                                  echo_header_t *out_header,
                                  uint8_t out_cookie[ECHO_COOKIE_LEN],
                                  uint8_t out_cluster_key[32]);

// BOOTSTRAP_ACK
echo_err_t echo_encode_bootstrap_ack(uint8_t *out, size_t out_cap, size_t *out_len,
                                      int64_t timestamp_ms, uint8_t status,
                                      uint32_t witness_uptime_seconds,
                                      const uint8_t cluster_key[32]);

// ─── Dispatcher ──────────────────────────────────────────────────────────────
// Handles one incoming UDP packet. Writes reply bytes into `out` and sets
// `*out_len`. Returns true if a reply should be sent.
bool echo_handle_packet(echo_state_t *state,
                        const uint8_t *data, size_t data_len,
                        const uint8_t src_ipv4[4], uint16_t src_port,
                        uint64_t now_ms,
                        uint8_t *out, size_t out_cap, size_t *out_len);

// ─── Persistent X25519 key (NVS) ────────────────────────────────────────────
// Load from NVS, generating + saving on first run. Returns:
//   0  — key loaded from NVS (normal case)
//   1  — key was just generated and persisted (first boot)
//  -1  — failure
int echo_key_load_or_generate(uint8_t out[32]);
