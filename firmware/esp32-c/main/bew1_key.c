// Persistent X25519 private key in NVS. First boot: generate + persist.
// Subsequent boots: load. The only thing we persist across reboots;
// everything else (cluster table, node table) is RAM-only by design (§1).
//
// Entropy: on first boot we call bootloader_random_enable() before
// generating the key. That powers up the ESP32 RF front-end, which
// activates the hardware RNG's true-random mode (seeded from analogue
// noise in the RF subsystem). Without it, esp_fill_random() is only
// pseudo-random per Espressif's docs. The RF front-end is turned back
// off immediately after — the witness itself never uses WiFi/BT.

#include "bew1.h"

#include <string.h>

#include "bootloader_random.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "bew1-key";
#define NS "bew1"
#define KEY "x25519priv"

// Collect entropy from the RF-seeded hardware RNG over a long window and
// fold it into a SHA-256 pool. Deliberately over-engineered for the
// one-time key: if any individual read is slightly correlated (startup
// conditions, early RF state), the hash over ~40 reads over ~2 s gives
// full 256-bit entropy.
static void collect_entropy(uint8_t out[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);

    // Mix the chip's MAC + boot counter-ish time as domain separation
    uint8_t domain[] = "bedrock-echo x25519 seed v1";
    mbedtls_sha256_update(&ctx, domain, sizeof(domain));

    // ~2 s of RF-seeded reads, spaced out so the RNG reseeds between reads.
    for (int i = 0; i < 40; ++i) {
        uint8_t chunk[32];
        esp_fill_random(chunk, 32);
        mbedtls_sha256_update(&ctx, chunk, 32);
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
}

int bew1_key_load_or_generate(uint8_t out[32]) {
    // Ensure NVS is initialised (caller should also do this at boot, but idempotent).
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    nvs_handle_t h;
    err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return -1;
    }

    size_t len = 32;
    err = nvs_get_blob(h, KEY, out, &len);
    if (err == ESP_OK && len == 32) {
        ESP_LOGI(TAG, "loaded X25519 private key from NVS");
        nvs_close(h);
        return 0;
    }

    // First-boot path — take our time collecting real entropy.
    ESP_LOGW(TAG, "=============================================");
    ESP_LOGW(TAG, "  FIRST BOOT: generating X25519 keypair      ");
    ESP_LOGW(TAG, "  This happens ONCE; board reboots after.    ");
    ESP_LOGW(TAG, "=============================================");
    ESP_LOGI(TAG, "  powering RF front-end for hardware entropy ...");
    bootloader_random_enable();
    // Long warm-up + SHA-256-mixed pool over many RNG reads (~2 s total).
    // Espressif uses ~10 ms in the bootloader; we go 200x that because
    // this only happens once per board and the cost of a weak key is
    // forever.
    vTaskDelay(pdMS_TO_TICKS(200));
    uint8_t seed[32];
    collect_entropy(seed);
    bootloader_random_disable();
    ESP_LOGI(TAG, "  RF front-end powered down; entropy pool ready");

    // Use the hashed seed as the X25519 private key (after RFC 7748 clamping).
    memcpy(out, seed, 32);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;

    uint8_t pub[32];
    if (!bew1_x25519_pub_from_priv(out, pub)) {
        ESP_LOGE(TAG, "x25519 pub_from_priv failed");
        nvs_close(h);
        return -1;
    }

    err = nvs_set_blob(h, KEY, out, 32);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_set_blob failed: %s", esp_err_to_name(err));
        nvs_close(h);
        return -1;
    }
    ESP_ERROR_CHECK(nvs_commit(h));
    nvs_close(h);
    ESP_LOGI(TAG, "X25519 private key persisted to NVS");
    return 1;  // signal first-boot path to caller
}
