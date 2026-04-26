// mDNS / DNS-SD announcement for the witness — see echo_mdns.h.

#include "echo_mdns.h"

#include <string.h>

#include "esp_log.h"
#include "mdns.h"
#include "mbedtls/base64.h"

static const char *TAG = "echo-mdns";

// Hostname the witness claims on the LAN. Operators can `ping <this>.local`.
#define ECHO_MDNS_HOSTNAME "bedrock-echo-witness"
#define ECHO_MDNS_INSTANCE "Bedrock Echo witness"
#define ECHO_MDNS_SERVICE_TYPE "_echo"
#define ECHO_MDNS_SERVICE_PROTO "_udp"

bool echo_mdns_announce(const echo_state_t *state) {
    esp_err_t err = mdns_init();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mdns_init failed: %s", esp_err_to_name(err));
        return false;
    }

    err = mdns_hostname_set(ECHO_MDNS_HOSTNAME);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mdns_hostname_set failed: %s", esp_err_to_name(err));
        return false;
    }
    mdns_instance_name_set(ECHO_MDNS_INSTANCE);

    // Base64-encode the X25519 public key (32 B → 44 chars incl. padding).
    // Same TXT format as the DNSSEC hosted scheme; one parser handles both
    // transports.
    char pub_b64[48] = {0};
    size_t pub_b64_len = 0;
    if (mbedtls_base64_encode((unsigned char *)pub_b64, sizeof(pub_b64),
                              &pub_b64_len, state->witness_pub, 32) != 0) {
        ESP_LOGW(TAG, "base64 encode of witness_pub failed");
        return false;
    }

    mdns_txt_item_t txt[] = {
        {"v", "Echo"},
        {"k", "x25519"},
        {"p", pub_b64},
    };

    err = mdns_service_add(
        ECHO_MDNS_INSTANCE,
        ECHO_MDNS_SERVICE_TYPE,
        ECHO_MDNS_SERVICE_PROTO,
        ECHO_UDP_PORT_DEFAULT,
        txt,
        sizeof(txt) / sizeof(txt[0])
    );
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mdns_service_add failed: %s", esp_err_to_name(err));
        return false;
    }

    ESP_LOGI(TAG, "advertising _echo._udp as %s.local on port %u",
             ECHO_MDNS_HOSTNAME, ECHO_UDP_PORT_DEFAULT);
    return true;
}
