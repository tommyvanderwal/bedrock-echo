// Bedrock Echo v1 (BEW1) — protocol types and constants for the C impl.
// See PROTOCOL.md in the repo root for the authoritative spec. Every value
// in this file corresponds directly to a numbered rule or table there.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ─── Wire constants (PROTOCOL.md §2, §3) ─────────────────────────────────────
#define BEW1_MAGIC "BEW1"
#define BEW1_HEADER_LEN 32u
#define BEW1_HMAC_LEN 32u
#define BEW1_MTU_CAP 1400u

#define BEW1_MSG_HEARTBEAT 0x01u
#define BEW1_MSG_STATUS_LIST 0x02u
#define BEW1_MSG_STATUS_DETAIL 0x03u
#define BEW1_MSG_UNKNOWN_SOURCE 0x10u
#define BEW1_MSG_BOOTSTRAP 0x20u
#define BEW1_MSG_BOOTSTRAP_ACK 0x21u

#define BEW1_NODE_PAYLOAD_MAX 128u
#define BEW1_LIST_ENTRY_LEN 16u
#define BEW1_LIST_MAX_ENTRIES 64u

#define BEW1_CLUSTER_KEY_LEN 32u
#define BEW1_SENDER_ID_LEN 8u
#define BEW1_EPH_PUBKEY_LEN 32u
#define BEW1_AEAD_TAG_LEN 16u
#define BEW1_AEAD_NONCE_LEN 12u
#define BEW1_BOOTSTRAP_INIT_PAYLOAD_MAX 96u

// ─── Witness state sizing (PROTOCOL.md §8) ──────────────────────────────────
#define BEW1_MAX_NODES 64u
#define BEW1_MAX_CLUSTERS 32u
#define BEW1_MAX_TRACKED_IPS 128u

#define BEW1_UDP_PORT_DEFAULT 7337u

// HKDF info string — must match Python/Rust impls byte-for-byte.
static const uint8_t BEW1_HKDF_INFO[] = "bedrock-echo v1 bootstrap";
#define BEW1_HKDF_INFO_LEN (sizeof(BEW1_HKDF_INFO) - 1u)  // exclude trailing \0

// ─── Errors (mirror Rust's Error enum) ──────────────────────────────────────
typedef enum {
    BEW1_OK = 0,
    BEW1_ERR_TOO_SHORT,
    BEW1_ERR_BAD_LENGTH,
    BEW1_ERR_BAD_MAGIC,
    BEW1_ERR_BAD_FLAGS,
    BEW1_ERR_BAD_MSG_TYPE,
    BEW1_ERR_ZERO_SENDER_ID,
    BEW1_ERR_BAD_PAYLOAD_LEN,
    BEW1_ERR_AUTH_FAILED,
    BEW1_ERR_BAD_FIELD,
    BEW1_ERR_OVER_MTU,
} bew1_err_t;

// ─── Packed header (32 bytes, big-endian) ───────────────────────────────────
typedef struct {
    uint8_t msg_type;
    uint8_t flags;
    uint8_t sender_id[BEW1_SENDER_ID_LEN];
    uint64_t sequence;
    int64_t timestamp_ms;
    uint16_t payload_len;
} bew1_header_t;

bew1_err_t bew1_header_pack(uint8_t out[BEW1_HEADER_LEN], const bew1_header_t *hdr);
bew1_err_t bew1_header_unpack(bew1_header_t *out, const uint8_t *buf, size_t len);

// Returns HMAC trailer length for a given msg_type, or 0xFF if unknown.
uint8_t bew1_trailer_len(uint8_t msg_type);
bool bew1_is_hmac_type(uint8_t msg_type);

// ─── Crypto (thin wrappers over mbedTLS) ────────────────────────────────────
void bew1_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t tag_out[32]);

bool bew1_hmac_verify(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      const uint8_t tag[32]);

// Generate a fresh X25519 keypair. Returns true on success.
bool bew1_x25519_generate(uint8_t priv_out[32], uint8_t pub_out[32]);

// Derive public key from private (for hot-loaded keys from NVS).
bool bew1_x25519_pub_from_priv(const uint8_t priv[32], uint8_t pub_out[32]);

// ECDH: shared = X25519(priv, peer_pub). 32-byte output.
bool bew1_x25519_shared(const uint8_t priv[32], const uint8_t peer_pub[32],
                        uint8_t shared_out[32]);

// HKDF-SHA256 with salt = 32 zero bytes and info = "bedrock-echo v1 bootstrap".
bool bew1_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                      uint8_t out[32]);

// ChaCha20-Poly1305 encrypt/decrypt with a zero nonce (single-use key).
// Writes ciphertext || 16-byte tag to `out` (out_len = pt_len + 16).
bool bew1_aead_encrypt(const uint8_t key[32],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *out);

// Decrypts `ct || tag`. On success writes plaintext into `out` (pt_len = ct_len - 16).
bool bew1_aead_decrypt(const uint8_t key[32],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *out);

// ─── State tables (RAM-only per PROTOCOL.md §8) ─────────────────────────────
typedef struct {
    bool in_use;
    uint8_t cluster_key[BEW1_CLUSTER_KEY_LEN];
    uint64_t bootstrapped_ms;
    uint8_t num_nodes;
} bew1_cluster_entry_t;

typedef struct {
    bool in_use;
    uint8_t sender_id[BEW1_SENDER_ID_LEN];
    uint8_t sender_ipv4[4];
    uint8_t cluster_slot;
    uint64_t last_rx_ms;
    uint64_t last_rx_sequence;
    uint64_t last_tx_sequence;
    uint8_t payload_len;
    uint8_t payload[BEW1_NODE_PAYLOAD_MAX];
} bew1_node_entry_t;

typedef struct {
    bool in_use;
    uint8_t ipv4[4];
    float tokens;
    uint64_t last_refill_ms;
    uint64_t last_unknown_ms;
} bew1_rate_entry_t;

typedef struct {
    uint8_t witness_priv[32];
    uint8_t witness_pub[32];
    uint8_t witness_sender_id[BEW1_SENDER_ID_LEN];
    uint64_t start_ms;
    bew1_cluster_entry_t clusters[BEW1_MAX_CLUSTERS];
    bew1_node_entry_t nodes[BEW1_MAX_NODES];
    bew1_rate_entry_t rate_limits[BEW1_MAX_TRACKED_IPS];
} bew1_state_t;

void bew1_state_init(bew1_state_t *state, const uint8_t priv[32], uint64_t now_ms);
uint64_t bew1_state_uptime_ms(const bew1_state_t *state, uint64_t now_ms);
void bew1_state_age_out(bew1_state_t *state, uint64_t now_ms);
bool bew1_state_allow(bew1_state_t *state, const uint8_t ipv4[4], uint64_t now_ms);
bool bew1_state_allow_unknown(bew1_state_t *state, const uint8_t ipv4[4],
                              uint64_t now_ms);

// Returns index of node entry or -1 if not found.
int bew1_state_find_node(const bew1_state_t *state, const uint8_t sender_id[8]);
int bew1_state_find_cluster_by_key(const bew1_state_t *state,
                                   const uint8_t key[32]);

// ─── Main dispatcher (§9) ───────────────────────────────────────────────────
// Handles one incoming UDP packet. Writes reply bytes into `out` and sets
// `*out_len`. Returns true if a reply should be sent.
bool bew1_handle_packet(bew1_state_t *state,
                        const uint8_t *data, size_t data_len,
                        const uint8_t src_ipv4[4],
                        uint64_t now_ms,
                        uint8_t *out, size_t out_cap, size_t *out_len);

// ─── Persistent X25519 key (NVS) ────────────────────────────────────────────
// Load the X25519 private key from NVS. `out` is 32 bytes. Returns:
//   0  — key loaded from NVS (normal case)
//   1  — key was just generated and persisted (first boot); caller should
//        print provisioning info + esp_restart() for a clean subsequent boot
//  -1  — failure
int bew1_key_load_or_generate(uint8_t out[32]);
