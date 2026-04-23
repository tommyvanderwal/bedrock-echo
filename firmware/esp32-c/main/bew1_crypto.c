// Minimal bedrock-grade crypto for Bedrock Echo on ESP32.
//
// * X25519 scalar-mult: embedded TweetNaCl reference impl (public domain).
//   Constant-time, standalone, zero dependencies, ~60 lines. Picked over
//   mbedTLS ECP because its Curve25519 path has too many config knobs that
//   vary across mbedTLS builds. This way our X25519 matches the RFC 7748
//   test vectors byte-for-byte on any target.
// * HMAC-SHA256, HKDF-SHA256, ChaCha20-Poly1305: mbedTLS (already in IDF).

#include "bew1.h"

#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

static const char *CRYPTO_TAG = "bew1-crypto";

// ─── HMAC-SHA256 ────────────────────────────────────────────────────────────

void bew1_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t tag_out[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md, 1) == 0) {
        mbedtls_md_hmac_starts(&ctx, key, key_len);
        mbedtls_md_hmac_update(&ctx, data, data_len);
        mbedtls_md_hmac_finish(&ctx, tag_out);
    }
    mbedtls_md_free(&ctx);
}

bool bew1_hmac_verify(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      const uint8_t tag[32]) {
    uint8_t computed[32];
    bew1_hmac_sha256(key, key_len, data, data_len, computed);
    return mbedtls_ct_memcmp(computed, tag, 32) == 0;
}

// ─── X25519 (TweetNaCl scalar-mult, public domain) ──────────────────────────
// Matches RFC 7748 exactly. Scalar and u-coordinate are 32 little-endian
// bytes each. TweetNaCl clamps the scalar inside; we pass the private key
// through unmodified.
// Source: https://tweetnacl.cr.yp.to/20140917/tweetnacl.c — D. J. Bernstein
// et al., public domain.

typedef int64_t gf[16];
static const gf _121665 = {0xDB41, 1};

static void car25519(gf o) {
    int i; int64_t c;
    for (i = 0; i < 16; ++i) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t t, c = ~(b - 1);
    int i;
    for (i = 0; i < 16; ++i) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n) {
    int i, j, b;
    gf m, t;
    for (i = 0; i < 16; ++i) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);
    for (j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; ++i) {
        o[2 * i] = t[i] & 0xff;
        o[2 * i + 1] = t[i] >> 8;
    }
}

static void unpack25519(gf o, const uint8_t *n) {
    int i;
    for (i = 0; i < 16; ++i)
        o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b) {
    int64_t t[31];
    int i, j;
    for (i = 0; i < 31; ++i) t[i] = 0;
    for (i = 0; i < 16; ++i)
        for (j = 0; j < 16; ++j)
            t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; ++i) o[i] = t[i];
    car25519(o); car25519(o);
}

static void S(gf o, const gf a) { M(o, a, a); }

static void inv25519(gf o, const gf i) {
    gf c;
    int a;
    for (a = 0; a < 16; ++a) c[a] = i[a];
    for (a = 253; a >= 0; --a) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    for (a = 0; a < 16; ++a) o[a] = c[a];
}

static int tweetnacl_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p) {
    uint8_t z[32];
    int64_t r;
    int i;
    gf x, a, b, c, d, e, f;
    for (i = 0; i < 31; ++i) z[i] = n[i];
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;
    unpack25519(x, p);
    for (i = 0; i < 16; ++i) { b[i] = x[i]; d[i] = a[i] = c[i] = 0; }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, _121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    inv25519(c, c);
    M(a, a, c);
    pack25519(q, a);
    return 0;
}

static const uint8_t CURVE25519_BASE[32] = {9, 0};  // rest is zero

bool bew1_x25519_pub_from_priv(const uint8_t priv[32], uint8_t pub_out[32]) {
    return tweetnacl_scalarmult(pub_out, priv, CURVE25519_BASE) == 0;
}

bool bew1_x25519_shared(const uint8_t priv[32], const uint8_t peer_pub[32],
                        uint8_t shared_out[32]) {
    return tweetnacl_scalarmult(shared_out, priv, peer_pub) == 0;
}

bool bew1_x25519_generate(uint8_t priv_out[32], uint8_t pub_out[32]) {
    // ESP32 has a hardware RNG exposed via esp_fill_random() — better
    // entropy source than mbedTLS's DRBD when Wi-Fi/BT are off (no phy init).
    esp_fill_random(priv_out, 32);

    // RFC 7748 clamping — makes the stored key canonical.
    priv_out[0] &= 248;
    priv_out[31] &= 127;
    priv_out[31] |= 64;

    if (!bew1_x25519_pub_from_priv(priv_out, pub_out)) {
        ESP_LOGE(CRYPTO_TAG, "x25519_pub_from_priv failed");
        return false;
    }
    return true;
}

// ─── HKDF-SHA256 ────────────────────────────────────────────────────────────

bool bew1_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, uint8_t out[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    static const uint8_t salt[32] = {0};  // all-zero 32-byte salt per spec
    return mbedtls_hkdf(md, salt, 32, ikm, ikm_len,
                        BEW1_HKDF_INFO, BEW1_HKDF_INFO_LEN,
                        out, 32) == 0;
}

// ─── ChaCha20-Poly1305 ──────────────────────────────────────────────────────

bool bew1_aead_encrypt(const uint8_t key[32],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *out) {
    static const uint8_t nonce[12] = {0};  // zero nonce safe for single-use key
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    bool ok = false;
    if (mbedtls_chachapoly_setkey(&ctx, key) != 0) goto out;
    // encrypt_and_tag: writes ct into out[..pt_len] and tag into out[pt_len..pt_len+16]
    if (mbedtls_chachapoly_encrypt_and_tag(&ctx, pt_len, nonce, aad, aad_len,
                                           pt, out, out + pt_len) != 0)
        goto out;
    ok = true;
out:
    mbedtls_chachapoly_free(&ctx);
    return ok;
}

bool bew1_aead_decrypt(const uint8_t key[32],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *out) {
    if (ct_len < 16) return false;
    static const uint8_t nonce[12] = {0};
    size_t pt_len = ct_len - 16;
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    bool ok = false;
    if (mbedtls_chachapoly_setkey(&ctx, key) != 0) goto out;
    if (mbedtls_chachapoly_auth_decrypt(&ctx, pt_len, nonce, aad, aad_len,
                                        ct + pt_len,   // tag
                                        ct,            // ciphertext
                                        out) != 0)
        goto out;
    ok = true;
out:
    mbedtls_chachapoly_free(&ctx);
    return ok;
}
