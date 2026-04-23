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

#include "bootloader_random.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "bew1-key";
#define NS "bew1"
#define KEY "x25519priv"

bool bew1_key_load_or_generate(uint8_t out[32]) {
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
        return false;
    }

    size_t len = 32;
    err = nvs_get_blob(h, KEY, out, &len);
    if (err == ESP_OK && len == 32) {
        ESP_LOGI(TAG, "loaded X25519 private key from NVS");
        nvs_close(h);
        return true;
    }

    ESP_LOGI(TAG, "generating fresh X25519 private key");
    ESP_LOGI(TAG, "  powering RF front-end for hardware entropy ...");
    bootloader_random_enable();
    // Let RF-noise-fed entropy accumulate before reading the RNG. 200 ms
    // is overkill (Espressif's bootloader uses ~10 ms) but this only
    // happens once in the device's lifetime, so err on the side of plenty.
    vTaskDelay(pdMS_TO_TICKS(200));

    uint8_t pub[32];
    bool gen_ok = bew1_x25519_generate(out, pub);

    bootloader_random_disable();
    ESP_LOGI(TAG, "  RF front-end powered down");

    if (!gen_ok) {
        ESP_LOGE(TAG, "x25519 generation failed");
        nvs_close(h);
        return false;
    }

    err = nvs_set_blob(h, KEY, out, 32);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_set_blob failed: %s", esp_err_to_name(err));
        nvs_close(h);
        return false;
    }
    ESP_ERROR_CHECK(nvs_commit(h));
    nvs_close(h);
    ESP_LOGI(TAG, "X25519 private key persisted to NVS");
    return true;
}
