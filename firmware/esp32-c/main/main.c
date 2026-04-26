// Bedrock Echo witness — Olimex ESP32-POE-ISO firmware (ESP-IDF / C).
// Boots, initialises Ethernet, loads (or generates) the witness X25519
// private key, binds UDP 12321, and runs the protocol dispatcher.

#include "echo.h"
#include "echo_eth.h"
#include "echo_info.h"
#include "echo_mdns.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "esp_eth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

static const char *TAG = "echo";

#define GOT_IPV4_BIT BIT0
static EventGroupHandle_t s_net_events;

static echo_state_t g_state;

static uint64_t now_ms(void) {
    return (uint64_t)(esp_timer_get_time() / 1000LL);
}

static void hex_dump(const char *label, const uint8_t *b, size_t n) {
    char buf[96];
    size_t off = 0;
    for (size_t i = 0; i < n && off + 3 < sizeof(buf); ++i) {
        off += snprintf(buf + off, sizeof(buf) - off, "%02x", b[i]);
    }
    buf[off] = 0;
    ESP_LOGI(TAG, "%s = %s", label, buf);
}

static void on_eth_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg; (void)base; (void)data;
    switch (id) {
        case ETHERNET_EVENT_CONNECTED: ESP_LOGI(TAG, "Ethernet link up"); break;
        case ETHERNET_EVENT_DISCONNECTED: ESP_LOGI(TAG, "Ethernet link down"); break;
        case ETHERNET_EVENT_START: ESP_LOGI(TAG, "Ethernet started"); break;
        case ETHERNET_EVENT_STOP: ESP_LOGI(TAG, "Ethernet stopped"); break;
    }
}

static void on_ip_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg; (void)base;
    if (id == IP_EVENT_ETH_GOT_IP) {
        ip_event_got_ip_t *evt = (ip_event_got_ip_t *)data;
        // Single DHCP-event announcement — the existing log line is easy
        // enough to parse with a "got IPv4 " prefix + IPv4 address.
        ESP_LOGI(TAG, "got IPv4 " IPSTR, IP2STR(&evt->ip_info.ip));
        ESP_LOGI(TAG, "  netmask " IPSTR, IP2STR(&evt->ip_info.netmask));
        ESP_LOGI(TAG, "  gateway " IPSTR, IP2STR(&evt->ip_info.gw));
        xEventGroupSetBits(s_net_events, GOT_IPV4_BIT);
    }
}

static void udp_server_task(void *arg) {
    (void)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { ESP_LOGE(TAG, "socket(): errno=%d", errno); vTaskDelete(NULL); }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(ECHO_UDP_PORT_DEFAULT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "bind(): errno=%d", errno);
        close(sock); vTaskDelete(NULL);
    }
    ESP_LOGI(TAG, "listening on UDP 0.0.0.0:%u", ECHO_UDP_PORT_DEFAULT);

    static uint8_t rx_buf[ECHO_MTU_CAP + 64];
    static uint8_t tx_buf[ECHO_MTU_CAP];

    while (1) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        int n = recvfrom(sock, rx_buf, sizeof(rx_buf), 0,
                         (struct sockaddr *)&src, &slen);
        if (n < 0) {
            ESP_LOGW(TAG, "recvfrom(): errno=%d", errno);
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        uint8_t src_ipv4[4];
        memcpy(src_ipv4, &src.sin_addr.s_addr, 4);
        uint16_t src_port = ntohs(src.sin_port);

        size_t out_len = 0;
        bool reply = echo_handle_packet(&g_state, rx_buf, (size_t)n,
                                         src_ipv4, src_port, now_ms(),
                                         tx_buf, sizeof(tx_buf), &out_len);
        if (reply && out_len > 0) {
            sendto(sock, tx_buf, out_len, 0, (struct sockaddr *)&src, slen);
        }
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "======================================");
    ESP_LOGI(TAG, "  Bedrock Echo witness — ESP32 (C)    ");
    ESP_LOGI(TAG, "  Board: Olimex ESP32-POE-ISO         ");
    ESP_LOGI(TAG, "  Protocol: Echo / UDP %u              ", ECHO_UDP_PORT_DEFAULT);
    ESP_LOGI(TAG, "======================================");

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_net_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID,
                                                &on_eth_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP,
                                                &on_ip_event, NULL));

    // 1. X25519 keypair — from NVS, or fresh on first boot.
    uint8_t priv[32];
    int key_status = echo_key_load_or_generate(priv);
    if (key_status < 0) {
        ESP_LOGE(TAG, "cannot load or generate X25519 private key");
        return;
    }

    // 2. Initialise RAM-only witness state.
    echo_state_init(&g_state, priv, now_ms());
    hex_dump("witness pub", g_state.witness_pub, 32);

    // 2a. If this was the first boot (key just generated), print the
    // provisioning info block and reboot into a clean steady-state boot.
    // Subsequent boots skip this and proceed straight to Ethernet.
    if (key_status == 1) {
        ESP_LOGW(TAG, "first-boot key generation complete — info block below, then reboot");
        // No netif yet, so `ip=` will show "(no DHCP yet)"; operator gets
        // pub + MAC on the serial console before the device joins the LAN.
        echo_info_print(&g_state, NULL);
        ESP_LOGW(TAG, "rebooting for a clean steady-state boot ...");
        vTaskDelay(pdMS_TO_TICKS(500));  // give the UART time to drain
        esp_restart();
        // (unreached)
    }

    // 3. Ethernet up + DHCP.
    esp_netif_t *netif = NULL;
    ESP_ERROR_CHECK(echo_eth_init(&netif));

    ESP_LOGI(TAG, "waiting for DHCP ...");
    xEventGroupWaitBits(s_net_events, GOT_IPV4_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    // 4. mDNS — advertise _echo._udp on the LAN. Best-effort; failures
    //    don't prevent the witness from running, just from being
    //    auto-discovered.
    echo_mdns_announce(&g_state);

    // 5. UDP task.
    xTaskCreate(udp_server_task, "echo-udp", 8192, NULL, 5, NULL);

    ESP_LOGI(TAG, "witness ready.");

    // 6. Print the provisioning info block (pub / senderid / MAC / IP)
    //    and start a tiny console that re-prints it on any serial input.
    echo_info_print(&g_state, netif);
    echo_info_start_console(&g_state, netif);
}
