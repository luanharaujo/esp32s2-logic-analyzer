#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_http_server.h"

// Prepara os 8 canais (GPIO dedicado) e o serviço de interrupção. is_busy: OTA em andamento;
// auth: confere o token nas rotas que acionam pinos (/gen).
esp_err_t capture_init(bool (*is_busy)(void), bool (*auth)(httpd_req_t *req));
// Registra /capture, /levels, /channels e /gen no servidor HTTP
void capture_register(httpd_handle_t server);
// Trava compartilhada entre a captura digital e a analógica (uma de cada vez). capture_is_busy: OTA.
bool capture_lock(uint32_t wait_ms);
void capture_unlock(void);
bool capture_is_busy(void);
// Registra /adc (captura analógica no ADC1, em adc_cap.c)
void adc_register(httpd_handle_t server);
