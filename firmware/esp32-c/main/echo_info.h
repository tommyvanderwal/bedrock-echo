#pragma once
// Provisioning-facing info block printed at boot and on any serial input.
// Exposes ONLY the public identifiers — X25519 pubkey, witness sender_id,
// Ethernet MAC, IP once DHCP lands, listening port. The private key never
// leaves the device.

#include "echo.h"
#include "esp_netif.h"

void echo_info_print(const echo_state_t *state, esp_netif_t *eth_netif);

// Start a tiny FreeRTOS task that reads stdin and re-prints the info block
// whenever a byte (typically Enter) arrives.
void echo_info_start_console(const echo_state_t *state, esp_netif_t *eth_netif);
