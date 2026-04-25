// Provisioning-facing serial info block. Deliberately tiny and machine-
// parseable. No dependency on fancy console libs.

#include "echo_info.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "esp_eth.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "echo-info";

// Kept at file scope so the console task can re-print without threading args.
static const echo_state_t *s_state = NULL;
static esp_netif_t *s_eth_netif = NULL;

static void hex_to(char *dst, const uint8_t *src, size_t n) {
    static const char HEX[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        dst[2 * i]     = HEX[src[i] >> 4];
        dst[2 * i + 1] = HEX[src[i] & 0xf];
    }
    dst[2 * n] = 0;
}

void echo_info_print(const echo_state_t *state, esp_netif_t *eth_netif) {
    char pub_hex[65];
    hex_to(pub_hex, state->witness_pub, 32);

    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_ETH);

    esp_netif_ip_info_t ip = {0};
    if (eth_netif) {
        esp_netif_get_ip_info(eth_netif, &ip);
    }

    // Machine-readable info block. Line-oriented key=value so a
    // provisioning script can grep -E '^(pub|mac|ip|port)='.
    // (No senderid — in v1 the witness's sender_id is fixed at 0xFF.)
    printf("\n");
    printf("===BEDROCK-ECHO-WITNESS===\n");
    printf("pub=%s\n", pub_hex);
    printf("mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    if (ip.ip.addr) {
        printf("ip=" IPSTR "\n", IP2STR(&ip.ip));
    } else {
        printf("ip=(no DHCP yet)\n");
    }
    printf("port=%u\n", ECHO_UDP_PORT_DEFAULT);
    printf("===END===\n");
    printf("\n");
    fflush(stdout);
}

static void console_task(void *arg) {
    (void)arg;
    while (1) {
        int c = getchar();
        if (c == EOF) {
            // VFS returns EOF when no data available — yield and retry
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        // Any input triggers a re-dump. Drain the rest of the line so the
        // next Enter causes exactly one more dump (simple but effective).
        while (c != '\n' && c != '\r' && c != EOF) {
            c = getchar();
            if (c == EOF) break;
        }
        if (s_state) echo_info_print(s_state, s_eth_netif);
    }
}

void echo_info_start_console(const echo_state_t *state, esp_netif_t *eth_netif) {
    s_state = state;
    s_eth_netif = eth_netif;
    // stdin is line-buffered by default via VFS; switch to unbuffered so
    // we see bytes as soon as they arrive.
    setvbuf(stdin, NULL, _IONBF, 0);
    xTaskCreate(console_task, "echo-console", 3072, NULL, 3, NULL);
    ESP_LOGI(TAG, "serial console ready (press Enter for info block)");
}
