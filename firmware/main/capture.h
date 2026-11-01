#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "esp_http_server.h"

// Sets up the 8 channels (dedicated GPIO) and the interrupt service. is_busy: OTA in progress;
// auth: checks the token on routes that drive pins (/gen).
esp_err_t capture_init(bool (*is_busy)(void), bool (*auth)(httpd_req_t *req));
// Registers /capture, /levels, /channels and /gen on the HTTP server.
void capture_register(httpd_handle_t server);
// Lock shared by digital and analog capture (one at a time). capture_is_busy: OTA.
bool capture_lock(uint32_t wait_ms);
void capture_unlock(void);
bool capture_is_busy(void);
// Registers /adc (analog capture on ADC1, in adc_cap.c).
void adc_register(httpd_handle_t server);
// Background ADC for the combined capture (adc_cap.c). adc_bg_open returns NULL or an error message.
const char *adc_bg_open(const char *pin, int rate, const char *atten, bool keep_digital);
uint32_t adc_bg_chain_samples(void);
uint32_t adc_bg_period_cycles(void);
void adc_bg_restart(uint32_t *t0);
uint32_t adc_bg_collect(uint16_t *buf, uint32_t n, uint32_t timeout_ms, uint32_t *invalid);
uint32_t adc_bg_mv(uint32_t raw);
int adc_bg_header(char *out, size_t n);
void adc_bg_close(void);
// Progress mark in RTC memory (survives a panic; becomes reset_detail on the next boot). "" = all ok.
void diag_mark(const char *what);
// true if the HTTP client closed the connection (to cancel a long wait).
bool client_gone(httpd_req_t *req);
uint32_t adc_bg_read(uint16_t *buf, uint32_t max, uint32_t timeout_ms, uint32_t *invalid);
// Channels (capture.c), for continuous recording (record.c).
int capture_ch_index(const char *name);
const char *capture_ch_name(int i);
void capture_apply_pull(const char *pull);
// Continuous recording (record.c).
void record_register(httpd_handle_t server);
bool record_discard_if_done(void);
