#pragma once
#include "esp_err.h"
#include "esp_netif.h"

esp_err_t echo_eth_init(esp_netif_t **out_netif);
