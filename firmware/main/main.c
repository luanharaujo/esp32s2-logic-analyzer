// Analisador lógico pela rede na Wi-Fi Devboard (clone preto, ESP32-S2) usada sozinha.
// Fase 1 (este arquivo): base de rede estável com OTA. Wi-Fi com gerente de BSSID (herdado
// do teclado USB), mDNS, HTTP (/status, /log, /scan, /ota, /reboot), LED RGB, Task Watchdog,
// log em RAM RTC e rollback de OTA. A captura de bordas entra depois, sempre por OTA.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_attr.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_https_ota.h"
#include "esp_http_client.h"
#include "esp_http_server.h"
#include "esp_task_wdt.h"
#include "esp_spi_flash.h"
#include "esp_chip_info.h"
#include "esp_mac.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"
#include "mdns.h"
#include "driver/gpio.h"
#include "mbedtls/sha256.h"
#include "capture.h"

#if __has_include("wifi_secrets.h")
#include "wifi_secrets.h"
#else
#warning "main/wifi_secrets.h ausente: Wi-Fi desligado (copie wifi_secrets.example.h)"
#define WIFI_SSID ""
#define WIFI_PASS ""
#define LA_TOKEN  ""
#endif
#ifndef WIFI_AVOID_BSSID_PREFIXES
#define WIFI_AVOID_BSSID_PREFIXES ""
#endif

#define HOSTNAME "logic-s2"
static const char *TAG = "S2LA";

// LED RGB da devboard: R=IO6, G=IO5, B=IO4, ânodo comum (aceso em nível baixo), como na
// devboard oficial. Confirmar no clone; se as cores saírem trocadas, ajustar aqui.
#define LED_R_GPIO 6
#define LED_G_GPIO 5
#define LED_B_GPIO 4
#define LED_ACTIVE_LOW 1

// ---------------------------------------------------------------------------------------
// Diagnóstico persistente (RTC slow memory, sobrevive a reset por software/panic/watchdog)
// ---------------------------------------------------------------------------------------
#define LOG_RING_SIZE 3072
#define RTC_DIAG_MAGIC 0x53324C41u  // "S2LA"
typedef struct {
    uint32_t magic;
    uint32_t boot_count;
    uint32_t last_uptime_s;
    char detail[48];
    uint32_t log_pos;
    uint32_t log_wrapped;
    char log[LOG_RING_SIZE];
} rtc_diag_t;
static RTC_NOINIT_ATTR rtc_diag_t rtc_diag;
static rtc_diag_t prev_diag;
static bool prev_diag_valid = false;
static portMUX_TYPE log_lock = portMUX_INITIALIZER_UNLOCKED;
static vprintf_like_t orig_vprintf = NULL;

static int ring_vprintf(const char *fmt, va_list args) {
    char tmp[200];
    va_list copy;
    va_copy(copy, args);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, copy);
    va_end(copy);
    if (n > 0) {
        if (n > (int)sizeof(tmp) - 1) n = sizeof(tmp) - 1;
        portENTER_CRITICAL(&log_lock);
        for (int i = 0; i < n; i++) {
            rtc_diag.log[rtc_diag.log_pos++] = tmp[i];
            if (rtc_diag.log_pos >= LOG_RING_SIZE) { rtc_diag.log_pos = 0; rtc_diag.log_wrapped = 1; }
        }
        portEXIT_CRITICAL(&log_lock);
    }
    return orig_vprintf ? orig_vprintf(fmt, args) : n;
}

static const char *reset_reason_str(void) {
    switch (esp_reset_reason()) {
        case ESP_RST_POWERON:   return "poweron";
        case ESP_RST_SW:        return "software";
        case ESP_RST_PANIC:     return "panic";
        case ESP_RST_INT_WDT:   return "int_wdt";
        case ESP_RST_TASK_WDT:  return "task_wdt";
        case ESP_RST_WDT:       return "wdt";
        case ESP_RST_BROWNOUT:  return "brownout";
        case ESP_RST_DEEPSLEEP: return "deepsleep";
        case ESP_RST_EXT:       return "external";
        default:                return "other";
    }
}

static void rtc_diag_boot(void) {
    esp_reset_reason_t why = esp_reset_reason();
    if (why != ESP_RST_POWERON && why != ESP_RST_BROWNOUT && rtc_diag.magic == RTC_DIAG_MAGIC &&
        rtc_diag.log_pos < LOG_RING_SIZE) {
        memcpy(&prev_diag, &rtc_diag, sizeof(prev_diag));
        prev_diag.detail[sizeof(prev_diag.detail) - 1] = '\0';
        prev_diag_valid = true;
    }
    uint32_t boots = prev_diag_valid ? prev_diag.boot_count + 1 : 1;
    memset(&rtc_diag, 0, sizeof(rtc_diag));
    rtc_diag.magic = RTC_DIAG_MAGIC;
    rtc_diag.boot_count = boots;
}

static void restart_with(const char *detail) {
    strlcpy(rtc_diag.detail, detail, sizeof(rtc_diag.detail));
    ESP_LOGW(TAG, "Reiniciando: %s", detail);
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_restart();
}

// ---------------------------------------------------------------------------------------
// LED
// ---------------------------------------------------------------------------------------
typedef enum { LED_BOOT, LED_NO_WIFI, LED_CONNECTING, LED_OK, LED_OTA, LED_ERROR } led_state_t;
static volatile led_state_t led_state = LED_BOOT;

static void led_rgb(bool r, bool g, bool b) {
    gpio_set_level(LED_R_GPIO, LED_ACTIVE_LOW ? !r : r);
    gpio_set_level(LED_G_GPIO, LED_ACTIVE_LOW ? !g : g);
    gpio_set_level(LED_B_GPIO, LED_ACTIVE_LOW ? !b : b);
}

// vermelho piscando = sem Wi-Fi; azul piscando = conectando; verde breve a cada 2 s = ok;
// magenta fixo = OTA em andamento; vermelho fixo = erro
static void led_task(void *pv) {
    uint32_t t = 0;
    while (1) {
        bool on = (t % 2) == 0;
        switch (led_state) {
            case LED_BOOT:       led_rgb(true, true, true); break;
            case LED_NO_WIFI:    led_rgb(on, false, false); break;
            case LED_CONNECTING: led_rgb(false, false, on); break;
            case LED_OK:         led_rgb(false, (t % 8) == 0, false); break;
            case LED_OTA:        led_rgb(true, false, true); break;
            case LED_ERROR:      led_rgb(true, false, false); break;
        }
        t++;
        vTaskDelay(pdMS_TO_TICKS(250));
    }
}

static void led_init(void) {
    gpio_config_t io = { .pin_bit_mask = (1ULL << LED_R_GPIO) | (1ULL << LED_G_GPIO) | (1ULL << LED_B_GPIO),
                         .mode = GPIO_MODE_OUTPUT };
    gpio_config(&io);
    led_rgb(false, false, false);
    xTaskCreate(led_task, "led", 2048, NULL, 2, NULL);
}

// ---------------------------------------------------------------------------------------
// Wi-Fi: gerente de BSSID (do teclado USB, 22/10/2026). Há dois APs "MINHA-REDE": o AP mesh (rede do
// Mac) e o modem a montante (outra sub-rede, inalcançável). Depois de um reset o AP mesh às
// vezes recusa a 1a autenticação e o driver, sozinho, cai no modem e fica lá. Aqui: varre,
// ordena por RSSI, põe por último os BSSIDs da lista de evitar (WIFI_AVOID_BSSID_PREFIXES,
// em wifi_secrets.h), insiste 4 vezes em cada um e, se acabou num AP evitado ou mais fraco,
// revê a cada 1 min (evitado) ou 5 min e troca quando o melhor aparecer.
// ---------------------------------------------------------------------------------------
static EventGroupHandle_t wifi_events;
#define WIFI_GOT_IP_BIT  BIT0
#define WIFI_DISCONN_BIT BIT1
#define WIFI_EVER_IP_BIT BIT2
#define WIFI_TRIES_PER_AP 4
#define WIFI_MAX_CAND 8

static volatile bool wifi_has_ip = false;
static char wifi_ip[16] = "", wifi_gw[16] = "";
static int64_t wifi_lost_since_us = 0;
static uint32_t wifi_connects = 0, wifi_disconnects = 0;
static uint8_t wifi_last_reason = 0;
static bool mdns_started = false;

typedef struct { uint8_t bssid[6]; int8_t rssi; uint8_t ch; bool avoid; } cand_t;

static bool bssid_avoided(const uint8_t *b) {
    const char *p = WIFI_AVOID_BSSID_PREFIXES;
    while (p && *p) {
        uint8_t pre[6]; int n = 0;
        while (*p && *p != ',' && n < 6) {
            unsigned v;
            if (sscanf(p, "%2x", &v) != 1) break;
            pre[n++] = (uint8_t)v;
            p += 2;
            if (*p == ':') p++;
        }
        if (n > 0 && memcmp(pre, b, n) == 0) return true;
        while (*p && *p != ',') p++;
        if (*p == ',') p++;
    }
    return false;
}

static int wifi_scan_candidates(cand_t *out) {
    wifi_scan_config_t sc = { .ssid = (uint8_t *)WIFI_SSID, .show_hidden = false };
    if (esp_wifi_scan_start(&sc, true) != ESP_OK) return 0;
    uint16_t n = 16;
    wifi_ap_record_t *aps = calloc(n, sizeof(*aps));
    if (!aps) return 0;
    esp_wifi_scan_get_ap_records(&n, aps);  // já ordenados por RSSI
    int c = 0;
    for (int pass = 0; pass < 2; pass++) {  // primeiro os bons, depois os evitados
        for (int i = 0; i < n && c < WIFI_MAX_CAND; i++) {
            if (strcmp((const char *)aps[i].ssid, WIFI_SSID) != 0) continue;
            bool avoid = bssid_avoided(aps[i].bssid);
            if (avoid != (pass == 1)) continue;
            memcpy(out[c].bssid, aps[i].bssid, 6);
            out[c].rssi = aps[i].rssi;
            out[c].ch = aps[i].primary;
            out[c].avoid = avoid;
            ESP_LOGI(TAG, "Wi-Fi candidato %d: " MACSTR " canal %d rssi %d%s", c, MAC2STR(aps[i].bssid),
                     aps[i].primary, aps[i].rssi, avoid ? " (evitado)" : "");
            c++;
        }
    }
    free(aps);
    return c;
}

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *d = (wifi_event_sta_disconnected_t *)data;
        wifi_last_reason = d->reason;
        if (wifi_has_ip) { wifi_disconnects++; wifi_lost_since_us = esp_timer_get_time(); }
        ESP_LOGW(TAG, "Wi-Fi desconectado de " MACSTR " (motivo %d)", MAC2STR(d->bssid), d->reason);
        wifi_has_ip = false;
        if (led_state != LED_OTA) led_state = LED_CONNECTING;
        xEventGroupSetBits(wifi_events, WIFI_DISCONN_BIT);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        snprintf(wifi_ip, sizeof(wifi_ip), IPSTR, IP2STR(&e->ip_info.ip));
        snprintf(wifi_gw, sizeof(wifi_gw), IPSTR, IP2STR(&e->ip_info.gw));
        ESP_LOGI(TAG, "IP %s gw %s", wifi_ip, wifi_gw);
        wifi_has_ip = true;
        wifi_connects++;
        wifi_lost_since_us = 0;
        if (led_state != LED_OTA) led_state = LED_OK;
        xEventGroupSetBits(wifi_events, WIFI_GOT_IP_BIT | WIFI_EVER_IP_BIT);
    }
}

static void wifi_manager_task(void *pv) {
    cand_t cand[WIFI_MAX_CAND];
    while (1) {
        led_state = LED_CONNECTING;
        int n = wifi_scan_candidates(cand);
        if (n == 0) {
            ESP_LOGW(TAG, "Wi-Fi: nenhum AP com SSID %s; nova varredura em 5 s", WIFI_SSID);
            led_state = LED_NO_WIFI;
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
        for (int c = 0; c < n; c++) {
            wifi_config_t cfg = { 0 };
            strlcpy((char *)cfg.sta.ssid, WIFI_SSID, sizeof(cfg.sta.ssid));
            strlcpy((char *)cfg.sta.password, WIFI_PASS, sizeof(cfg.sta.password));
            cfg.sta.bssid_set = true;
            cfg.sta.channel = cand[c].ch;
            memcpy(cfg.sta.bssid, cand[c].bssid, 6);
            esp_wifi_set_config(WIFI_IF_STA, &cfg);
            bool got = false;
            for (int t = 0; t < WIFI_TRIES_PER_AP && !got; t++) {
                ESP_LOGI(TAG, "Wi-Fi: conectando em " MACSTR " (tentativa %d)", MAC2STR(cand[c].bssid), t + 1);
                xEventGroupClearBits(wifi_events, WIFI_GOT_IP_BIT | WIFI_DISCONN_BIT);
                esp_wifi_connect();
                EventBits_t b = xEventGroupWaitBits(wifi_events, WIFI_GOT_IP_BIT | WIFI_DISCONN_BIT, pdFALSE,
                                                    pdFALSE, pdMS_TO_TICKS(15000));
                got = (b & WIFI_GOT_IP_BIT) && !(b & WIFI_DISCONN_BIT);
                if (!got) {
                    esp_wifi_disconnect();
                    vTaskDelay(pdMS_TO_TICKS(1000 + 1000 * t));
                }
            }
            if (!got) continue;
            uint32_t recheck_ms = cand[c].avoid ? 60 * 1000 : 5 * 60 * 1000;
            while (1) {
                EventBits_t b = xEventGroupWaitBits(wifi_events, WIFI_DISCONN_BIT, pdFALSE, pdFALSE,
                                                    pdMS_TO_TICKS(recheck_ms));
                if (b & WIFI_DISCONN_BIT) break;
                if (c == 0) continue;
                cand_t nb[WIFI_MAX_CAND];
                int m = wifi_scan_candidates(nb);
                if (m > 0 && memcmp(nb[0].bssid, cand[c].bssid, 6) != 0 && (cand[c].avoid || !nb[0].avoid)) {
                    ESP_LOGW(TAG, "Wi-Fi: AP preferido disponível, trocando");
                    esp_wifi_disconnect();
                    break;
                }
            }
            break;  // caiu: varre de novo
        }
    }
}

// ---------------------------------------------------------------------------------------
// OTA (POST /ota com o .bin no corpo, ou POST /ota?url=... para o ESP baixar) + rollback
// ---------------------------------------------------------------------------------------
static volatile bool ota_busy = false;
static char ota_last[96] = "";
static bool ota_pending_verify = false;

static void restart_task(void *pv) {
    vTaskDelay(pdMS_TO_TICKS(800));
    restart_with((const char *)pv);
}

static void ota_url_task(void *pv) {
    char *url = (char *)pv;
    esp_http_client_config_t http = { .url = url, .timeout_ms = 15000, .keep_alive_enable = true };
    ESP_LOGI(TAG, "OTA: baixando %s", url);
    esp_err_t err = esp_https_ota(&http);  // IDF 4.4: recebe a config do http_client
    free(url);
    if (err == ESP_OK) {
        strlcpy(ota_last, "ok (url)", sizeof(ota_last));
        restart_with("ota_url");
    }
    snprintf(ota_last, sizeof(ota_last), "erro url: %s", esp_err_to_name(err));
    ESP_LOGE(TAG, "OTA: %s", ota_last);
    ota_busy = false;
    led_state = wifi_has_ip ? LED_OK : LED_CONNECTING;
    vTaskDelete(NULL);
}

// O novo firmware fica "pendente" até provar que sobe a rede. Se não conseguir IP + HTTP em
// 3 min, o supervisor manda voltar para o anterior.
static void ota_rollback_check_boot(void) {
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;
    if (esp_ota_get_state_partition(run, &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY) {
        ota_pending_verify = true;
        ESP_LOGW(TAG, "Firmware novo pendente de validação (rollback em 180 s se a rede não subir)");
    }
}

// ---------------------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------------------
static bool token_ok(httpd_req_t *req) {
    char tok[80];
    if (strlen(LA_TOKEN) == 0) return true;
    if (httpd_req_get_hdr_value_str(req, "X-Token", tok, sizeof(tok)) == ESP_OK && strcmp(tok, LA_TOKEN) == 0)
        return true;
    httpd_resp_set_status(req, "403 Forbidden");
    httpd_resp_sendstr(req, "{\"ok\":false,\"err\":\"token\"}\n");
    return false;
}

static void json_reply(httpd_req_t *req, const char *body) {
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_sendstr(req, body);
}

static bool is_ota_busy(void) { return ota_busy; }

static esp_err_t status_handler(httpd_req_t *req) {
    static char buf[1400];
    const esp_app_desc_t *app = esp_ota_get_app_description();
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    wifi_ap_record_t ap;
    bool have_ap = wifi_has_ip && esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
    size_t psram = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    snprintf(buf, sizeof(buf),
             "{\"ok\":true,\"name\":\"%s\",\"fw\":\"%s\",\"built\":\"%s %s\",\"idf\":\"%s\",\"partition\":\"%s\","
             "\"ota_pending_verify\":%s,\"ota_last\":\"%s\",\"uptime_s\":%lld,\"reset_reason\":\"%s\","
             "\"reset_detail\":\"%s\",\"prev_uptime_s\":%lu,\"boot\":%lu,"
             "\"ssid\":\"%s\",\"bssid\":\"" MACSTR "\",\"ch\":%d,\"rssi\":%d,\"ip\":\"%s\",\"gw\":\"%s\","
             "\"wifi_connects\":%lu,\"wifi_disconnects\":%lu,\"wifi_last_reason\":%u,"
             "\"mac\":\"" MACSTR "\",\"chip_rev\":%d,\"flash_mb\":%u,\"psram_kb\":%u,\"heap_free\":%u,\"heap_min\":%u}\n",
             HOSTNAME, app->version, app->date, app->time, app->idf_ver, run ? run->label : "?",
             ota_pending_verify ? "true" : "false", ota_last, esp_timer_get_time() / 1000000,
             reset_reason_str(), prev_diag_valid ? prev_diag.detail : "",
             prev_diag_valid ? (unsigned long)prev_diag.last_uptime_s : 0UL, (unsigned long)rtc_diag.boot_count,
             have_ap ? (const char *)ap.ssid : "", MAC2STR(have_ap ? ap.bssid : (uint8_t[6]){0}),
             have_ap ? ap.primary : 0, have_ap ? ap.rssi : 0, wifi_ip, wifi_gw,
             (unsigned long)wifi_connects, (unsigned long)wifi_disconnects, wifi_last_reason,
             MAC2STR(mac), chip.revision, (unsigned)(spi_flash_get_chip_size() >> 20), (unsigned)(psram / 1024),
             (unsigned)esp_get_free_heap_size(), (unsigned)esp_get_minimum_free_heap_size());
    json_reply(req, buf);
    return ESP_OK;
}

static esp_err_t root_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req,
        "logic-s2: analisador logico (ESP32-S2)\n"
        "GET  /status          estado em JSON\n"
        "GET  /log[?prev=1]    log em RAM (do boot atual ou do anterior)\n"
        "GET  /scan            APs visiveis\n"
        "POST /ota             corpo = firmware .bin (header X-Token, opcional X-SHA256)\n"
        "POST /ota?url=URL     o ESP baixa o .bin (header X-Token)\n"
        "POST /reboot          (header X-Token)\n"
        "GET  /channels        mapa dos 8 canais\n"
        "GET  /levels[?pull=]  nivel atual dos canais\n"
        "GET  /capture?ms=100&trigger=IO10&edge=fall&timeout_ms=10000&pull=up&pins=IO10,IO11\n"
        "                      CSV de bordas (formato gpio_edges v1, ciclos de 240 MHz)\n"
        "POST /gen?pin=IO10&hz=1000&duty=50   gerador de teste no canal (hz=0 desliga; X-Token)\n");
    return ESP_OK;
}

static esp_err_t log_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/plain");
    char q[32] = "";
    bool want_prev = httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK && strstr(q, "prev=1");
    static char snap[LOG_RING_SIZE];
    size_t pos;
    bool wrapped;
    if (want_prev) {
        if (!prev_diag_valid) { httpd_resp_sendstr(req, "sem log do boot anterior (poweron)\n"); return ESP_OK; }
        char hdr[128];
        snprintf(hdr, sizeof(hdr), "# boot %lu, viveu %lu s, motivo: '%s'\n", (unsigned long)prev_diag.boot_count,
                 (unsigned long)prev_diag.last_uptime_s, prev_diag.detail);
        httpd_resp_send_chunk(req, hdr, strlen(hdr));
        memcpy(snap, prev_diag.log, LOG_RING_SIZE);
        pos = prev_diag.log_pos;
        wrapped = prev_diag.log_wrapped;
    } else {
        portENTER_CRITICAL(&log_lock);
        memcpy(snap, rtc_diag.log, LOG_RING_SIZE);
        pos = rtc_diag.log_pos;
        wrapped = rtc_diag.log_wrapped;
        portEXIT_CRITICAL(&log_lock);
    }
    if (wrapped) httpd_resp_send_chunk(req, snap + pos, LOG_RING_SIZE - pos);
    httpd_resp_send_chunk(req, snap, pos);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t scan_handler(httpd_req_t *req) {
    wifi_scan_config_t sc = { .show_hidden = false };
    if (esp_wifi_scan_start(&sc, true) != ESP_OK) { json_reply(req, "{\"ok\":false,\"err\":\"scan\"}\n"); return ESP_OK; }
    uint16_t n = 20;
    wifi_ap_record_t *aps = calloc(n, sizeof(*aps));
    if (!aps) return ESP_FAIL;
    esp_wifi_scan_get_ap_records(&n, aps);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send_chunk(req, "{\"ok\":true,\"aps\":[", HTTPD_RESP_USE_STRLEN);
    for (int i = 0; i < n; i++) {
        char line[160];
        snprintf(line, sizeof(line), "%s{\"ssid\":\"%s\",\"bssid\":\"" MACSTR "\",\"ch\":%d,\"rssi\":%d,\"avoid\":%s}",
                 i ? "," : "", (const char *)aps[i].ssid, MAC2STR(aps[i].bssid), aps[i].primary, aps[i].rssi,
                 bssid_avoided(aps[i].bssid) ? "true" : "false");
        httpd_resp_send_chunk(req, line, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, "]}\n", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    free(aps);
    return ESP_OK;
}

static esp_err_t reboot_handler(httpd_req_t *req) {
    if (!token_ok(req)) return ESP_OK;
    json_reply(req, "{\"ok\":true,\"reboot\":true}\n");
    xTaskCreate(restart_task, "restart", 2048, (void *)"http_reboot", 5, NULL);
    return ESP_OK;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void url_decode(char *s) {
    char *o = s;
    for (; *s; s++) {
        if (*s == '%' && hexval(s[1]) >= 0 && hexval(s[2]) >= 0) { *o++ = (char)(hexval(s[1]) * 16 + hexval(s[2])); s += 2; }
        else *o++ = *s;
    }
    *o = '\0';
}

static esp_err_t ota_handler(httpd_req_t *req) {
    if (!token_ok(req)) return ESP_OK;
    if (ota_busy) { json_reply(req, "{\"ok\":false,\"err\":\"ota em andamento\"}\n"); return ESP_OK; }

    char q[300];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        char *url = calloc(1, 290);
        if (url && httpd_query_key_value(q, "url", url, 290) == ESP_OK && strlen(url) > 0) {
            url_decode(url);
            ota_busy = true;
            led_state = LED_OTA;
            json_reply(req, "{\"ok\":true,\"mode\":\"url\",\"note\":\"baixando; o ESP reinicia sozinho\"}\n");
            xTaskCreate(ota_url_task, "ota_url", 8192, url, 5, NULL);
            return ESP_OK;
        }
        free(url);
    }

    int total = req->content_len;
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (total <= 0 || !part || total > (int)part->size) {
        snprintf(ota_last, sizeof(ota_last), "tamanho invalido (%d)", total);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, ota_last);
        return ESP_OK;
    }
    char sha_hex[72] = "";
    bool want_sha = httpd_req_get_hdr_value_str(req, "X-SHA256", sha_hex, sizeof(sha_hex)) == ESP_OK &&
                    strlen(sha_hex) == 64;

    ota_busy = true;
    led_state = LED_OTA;
    ESP_LOGI(TAG, "OTA: recebendo %d bytes para %s", total, part->label);
    esp_ota_handle_t h = 0;
    esp_err_t err = esp_ota_begin(part, total, &h);
    if (err != ESP_OK) goto fail;
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    static char buf[4096];
    int got = 0, timeouts = 0;
    while (got < total) {
        int r = httpd_req_recv(req, buf, MIN(sizeof(buf), (size_t)(total - got)));
        if (r == HTTPD_SOCK_ERR_TIMEOUT && ++timeouts < 5) continue;
        if (r <= 0) { err = ESP_FAIL; esp_ota_abort(h); mbedtls_sha256_free(&sha); goto fail; }
        timeouts = 0;
        mbedtls_sha256_update(&sha, (const unsigned char *)buf, r);
        err = esp_ota_write(h, buf, r);
        if (err != ESP_OK) { esp_ota_abort(h); mbedtls_sha256_free(&sha); goto fail; }
        got += r;
    }
    unsigned char dig[32];
    mbedtls_sha256_finish(&sha, dig);
    mbedtls_sha256_free(&sha);
    if (want_sha) {
        char hex[65];
        for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", dig[i]);
        for (char *p = sha_hex; *p; p++) if (*p >= 'A' && *p <= 'F') *p += 32;
        if (strcmp(hex, sha_hex) != 0) {
            esp_ota_abort(h);
            strlcpy(ota_last, "sha256 diferente", sizeof(ota_last));
            ota_busy = false;
            led_state = LED_OK;
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, ota_last);
            return ESP_OK;
        }
    }
    err = esp_ota_end(h);  // valida a imagem (cabeçalho, checksum)
    if (err != ESP_OK) goto fail;
    err = esp_ota_set_boot_partition(part);
    if (err != ESP_OK) goto fail;
    snprintf(ota_last, sizeof(ota_last), "ok %d bytes -> %s", total, part->label);
    ESP_LOGI(TAG, "OTA: %s; reiniciando", ota_last);
    char reply[160];
    snprintf(reply, sizeof(reply), "{\"ok\":true,\"bytes\":%d,\"partition\":\"%s\",\"reboot\":true}\n", total, part->label);
    json_reply(req, reply);
    xTaskCreate(restart_task, "restart", 2048, (void *)"ota_http", 5, NULL);
    return ESP_OK;

fail:
    snprintf(ota_last, sizeof(ota_last), "erro: %s (recebido parcial)", esp_err_to_name(err));
    ESP_LOGE(TAG, "OTA: %s", ota_last);
    ota_busy = false;
    led_state = wifi_has_ip ? LED_OK : LED_CONNECTING;
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, ota_last);
    return ESP_OK;
}

static bool http_started = false;

static void start_http(void) {
    httpd_handle_t server = NULL;
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.stack_size = 8192;
    cfg.max_uri_handlers = 16;
    cfg.lru_purge_enable = true;
    cfg.recv_wait_timeout = 10;
    if (httpd_start(&server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "HTTP não subiu");
        return;
    }
    const httpd_uri_t uris[] = {
        { .uri = "/",       .method = HTTP_GET,  .handler = root_handler },
        { .uri = "/status", .method = HTTP_GET,  .handler = status_handler },
        { .uri = "/log",    .method = HTTP_GET,  .handler = log_handler },
        { .uri = "/scan",   .method = HTTP_GET,  .handler = scan_handler },
        { .uri = "/ota",    .method = HTTP_POST, .handler = ota_handler },
        { .uri = "/reboot", .method = HTTP_POST, .handler = reboot_handler },
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) httpd_register_uri_handler(server, &uris[i]);
    capture_register(server);
    http_started = true;
    ESP_LOGI(TAG, "HTTP em :80");
}

static void start_mdns(void) {
    if (mdns_started) return;
    if (mdns_init() != ESP_OK) { ESP_LOGE(TAG, "mDNS falhou"); return; }
    mdns_hostname_set(HOSTNAME);
    mdns_instance_name_set("Analisador logico ESP32-S2");
    mdns_txt_item_t txt[] = { { "fw", esp_ota_get_app_description()->version }, { "path", "/status" } };
    mdns_service_add(NULL, "_http", "_tcp", 80, txt, 2);
    mdns_started = true;
    ESP_LOGI(TAG, "mDNS: %s.local", HOSTNAME);
}

// ---------------------------------------------------------------------------------------
// Supervisor: alimenta o Task Watchdog (panic em 10 s se travar), valida/rola de volta a
// OTA e reinicia se ficar 15 min sem Wi-Fi depois de já ter conectado.
// ---------------------------------------------------------------------------------------
#define OTA_VERIFY_DEADLINE_S 180
#define OTA_VERIFY_STABLE_S   20
#define WIFI_LOST_RESTART_US  (15LL * 60 * 1000000)

static void supervisor_task(void *pv) {
    ESP_ERROR_CHECK(esp_task_wdt_add(NULL));
    int64_t ip_since_us = 0;
    while (1) {
        esp_task_wdt_reset();
        int64_t now = esp_timer_get_time();
        rtc_diag.last_uptime_s = (uint32_t)(now / 1000000);
        if (wifi_has_ip && !ip_since_us) ip_since_us = now;
        if (!wifi_has_ip) ip_since_us = 0;
        if (ota_pending_verify) {
            if (wifi_has_ip && http_started && ip_since_us && now - ip_since_us > OTA_VERIFY_STABLE_S * 1000000LL) {
                esp_ota_mark_app_valid_cancel_rollback();
                ota_pending_verify = false;
                ESP_LOGI(TAG, "Firmware novo validado (rede ok por %d s)", OTA_VERIFY_STABLE_S);
            } else if (now > OTA_VERIFY_DEADLINE_S * 1000000LL) {
                strlcpy(rtc_diag.detail, "ota_rollback", sizeof(rtc_diag.detail));
                ESP_LOGE(TAG, "Firmware novo sem rede em %d s: voltando ao anterior", OTA_VERIFY_DEADLINE_S);
                vTaskDelay(pdMS_TO_TICKS(200));
                esp_ota_mark_app_invalid_rollback_and_reboot();
            }
        }
        if (!wifi_has_ip && wifi_lost_since_us && now - wifi_lost_since_us > WIFI_LOST_RESTART_US && !ota_busy) {
            restart_with("wifi_lost_15min");
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void app_main(void) {
    rtc_diag_boot();
    orig_vprintf = esp_log_set_vprintf(ring_vprintf);
    led_init();
    const esp_app_desc_t *app = esp_ota_get_app_description();
    ESP_LOGI(TAG, "Boot %s #%lu, reset=%s, detalhe anterior='%s', viveu %lu s", app->version,
             (unsigned long)rtc_diag.boot_count, reset_reason_str(), prev_diag_valid ? prev_diag.detail : "",
             prev_diag_valid ? (unsigned long)prev_diag.last_uptime_s : 0UL);
    ota_rollback_check_boot();
    capture_init(is_ota_busy, token_ok);
    xTaskCreate(supervisor_task, "supervisor", 3072, NULL, 10, NULL);

    esp_err_t r = nvs_flash_init();
    if (r == ESP_ERR_NVS_NO_FREE_PAGES || r == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        r = nvs_flash_init();
    }
    ESP_ERROR_CHECK(r);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *sta = esp_netif_create_default_wifi_sta();
    esp_netif_set_hostname(sta, HOSTNAME);
    wifi_events = xEventGroupCreate();

    if (strlen(WIFI_SSID) == 0) {
        ESP_LOGE(TAG, "Sem wifi_secrets.h: sem rede");
        led_state = LED_ERROR;
        return;
    }
    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wcfg));
    esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &wifi_event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL);
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_ps(WIFI_PS_NONE);  // latência baixa e estável para HTTP; a placa fica na tomada
    xTaskCreate(wifi_manager_task, "wifi_mgr", 4096, NULL, 4, NULL);

    xEventGroupWaitBits(wifi_events, WIFI_EVER_IP_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    start_mdns();
    start_http();
}
