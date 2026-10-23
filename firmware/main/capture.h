#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
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
// ADC em segundo plano para a captura combinada (adc_cap.c). adc_bg_open devolve NULL ou a mensagem de erro.
const char *adc_bg_open(const char *pin, int rate, const char *atten, bool keep_digital);
uint32_t adc_bg_chain_samples(void);
uint32_t adc_bg_period_cycles(void);
void adc_bg_restart(uint32_t *t0);
uint32_t adc_bg_collect(uint16_t *buf, uint32_t n, uint32_t timeout_ms, uint32_t *invalid);
uint32_t adc_bg_mv(uint32_t raw);
int adc_bg_header(char *out, size_t n);
void adc_bg_close(void);
// Marca de progresso em RTC (sobrevive a panic; vira reset_detail no boot seguinte). "" = tudo ok.
void diag_mark(const char *what);
// true se o cliente HTTP fechou a conexão (para cancelar uma espera longa)
bool client_gone(httpd_req_t *req);
