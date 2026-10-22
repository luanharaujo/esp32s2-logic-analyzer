// Captura de bordas nos 8 canais sem solda da devboard.
//
// Método: os 8 GPIOs viram um "bundle" de GPIO dedicado do ESP32-S2 (instrução get_gpio_in, 1 ciclo,
// lê os 8 de uma vez). Um laço em IRAM, com interrupções mascaradas, lê os pinos e o contador de ciclos
// (240 MHz, 4,17 ns) e grava só as mudanças. Cada volta do laço leva poucos ciclos (o max_gap_cycles do
// CSV diz quanto), então a resolução é de dezenas de ns, bem melhor que 1 µs.
// Trigger: interrupção de GPIO na borda pedida; a captura roda dentro da própria ISR (latência de ~1 a
// 2 µs entre a borda real e o t=0). Sem trigger, a captura começa na hora.
// Limites: janela de até CAP_MAX_MS (Wi-Fi e ticks ficam parados durante a janela) e o buffer de bordas
// (RAM interna livre). Sem pré-trigger por enquanto.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <stddef.h>
#include <strings.h>
#include "esp_timer.h"
#include "soc/gpio_struct.h"
#include "xtensa/xtruntime.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_cpu.h"
#include "driver/gpio.h"
#include "driver/dedic_gpio.h"
#include "driver/ledc.h"
#include "hal/cpu_ll.h"
#include "xtensa/core-macros.h"
#include "capture.h"

static const char *TAG = "CAP";

#define CPU_HZ 240000000u
#define N_CH 8
#define CAP_MAX_MS 2000
#define TRIG_MAX_TIMEOUT_MS 60000

// Ordem dos canais = bits do bundle. Nome = rótulo na devboard. Pino = número no header do Flipper.
static const int ch_gpio[N_CH] = { 10, 11, 12, 13, 1, 2, 18, 17 };
static const char *ch_name[N_CH] = { "IO10", "IO11", "IO12", "IO13", "IO1", "IO2", "IO18", "IO17" };
static const int ch_header_pin[N_CH] = { 5, 2, 4, 3, 10, 12, 15, 16 };

static dedic_gpio_bundle_handle_t bundle = NULL;
static SemaphoreHandle_t cap_lock = NULL;
static bool (*busy_check)(void) = NULL;
static bool (*auth_check)(httpd_req_t *) = NULL;

// Estado de uma captura (usado dentro da ISR: tudo em DRAM)
typedef struct {
    uint32_t *t;        // ciclos desde o início
    uint8_t *v;         // nível dos 8 canais depois da borda
    uint32_t max_edges;
    uint32_t n;
    uint32_t overflow;
    uint32_t max_gap;
    uint32_t win_cycles;
    uint32_t loops;
    uint8_t initial;
    uint8_t final;
    int trig_ch;        // -1 = sem trigger
    volatile bool done;
    SemaphoreHandle_t done_sem;
} cap_t;
static DRAM_ATTR cap_t cap;

static inline uint32_t IRAM_ATTR read_in(void) { return cpu_ll_read_dedic_gpio_in() & 0xFF; }

// O laço quente. Chamado com interrupções mascaradas.
static void IRAM_ATTR capture_loop(uint32_t last) {
    uint32_t *t = cap.t;
    uint8_t *v = cap.v;
    uint32_t n = 0, max_edges = cap.max_edges, win = cap.win_cycles, max_gap = 0, loops = 0;
    uint32_t start = XTHAL_GET_CCOUNT(), prev = start;
    while (1) {
        uint32_t now = XTHAL_GET_CCOUNT();
        uint32_t in = read_in();
        if (in != last) {
            if (n >= max_edges) { cap.overflow = 1; last = in; break; }
            t[n] = now - start;
            v[n] = (uint8_t)in;
            n++;
            last = in;
        }
        uint32_t gap = now - prev;
        if (gap > max_gap) max_gap = gap;
        prev = now;
        loops++;
        if (now - start > win) break;
    }
    cap.n = n;
    cap.max_gap = max_gap;
    cap.loops = loops;
    cap.final = (uint8_t)last;
}

// Desliga a interrupção do pino direto no registrador (seguro dentro da ISR)
static inline void IRAM_ATTR gpio_ll_intr_disable_irq(int gpio) { GPIO.pin[gpio].int_type = 0; }

static void IRAM_ATTR trigger_isr(void *arg) {
    if (cap.done) return;
    gpio_ll_intr_disable_irq(ch_gpio[cap.trig_ch]);
    uint32_t ps = XTOS_SET_INTLEVEL(XCHAL_EXCM_LEVEL);
    capture_loop(cap.initial);
    XTOS_RESTORE_INTLEVEL(ps);
    cap.done = true;
    BaseType_t hp = pdFALSE;
    xSemaphoreGiveFromISR(cap.done_sem, &hp);
    if (hp) portYIELD_FROM_ISR();
}

esp_err_t capture_init(bool (*is_busy)(void), bool (*auth)(httpd_req_t *)) {
    busy_check = is_busy;
    auth_check = auth;
    cap_lock = xSemaphoreCreateMutex();
    cap.done_sem = xSemaphoreCreateBinary();
    for (int i = 0; i < N_CH; i++) {
        gpio_reset_pin(ch_gpio[i]);
        gpio_set_direction(ch_gpio[i], GPIO_MODE_INPUT);
        gpio_set_pull_mode(ch_gpio[i], GPIO_FLOATING);
    }
    dedic_gpio_bundle_config_t cfg = { .gpio_array = ch_gpio, .array_size = N_CH, .flags = { .in_en = 1 } };
    esp_err_t err = dedic_gpio_new_bundle(&cfg, &bundle);
    if (err != ESP_OK) { ESP_LOGE(TAG, "bundle: %s", esp_err_to_name(err)); return err; }
    err = gpio_install_isr_service(ESP_INTR_FLAG_IRAM);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return err;
    ESP_LOGI(TAG, "8 canais prontos (dedicated GPIO)");
    return ESP_OK;
}

static int ch_index(const char *name) {
    for (int i = 0; i < N_CH; i++) {
        if (strcasecmp(name, ch_name[i]) == 0) return i;
        if ((name[0] == 'c' || name[0] == 'C') && (name[1] == 'h' || name[1] == 'H') && atoi(name + 2) == i &&
            name[2] >= '0' && name[2] <= '9')
            return i;
        if (atoi(name) == ch_gpio[i] && name[0] >= '0' && name[0] <= '9') return i;
    }
    return -1;
}

static void apply_pull(const char *pull) {
    gpio_pull_mode_t m = GPIO_FLOATING;
    if (strcmp(pull, "up") == 0) m = GPIO_PULLUP_ONLY;
    else if (strcmp(pull, "down") == 0) m = GPIO_PULLDOWN_ONLY;
    for (int i = 0; i < N_CH; i++) gpio_set_pull_mode(ch_gpio[i], m);
}

static bool qparam(const char *q, const char *key, char *out, size_t n) {
    return q && httpd_query_key_value(q, key, out, n) == ESP_OK;
}

// GET /levels: nível atual de cada canal
static esp_err_t levels_handler(httpd_req_t *req) {
    char q[64] = "", pull[8] = "";
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK && qparam(q, "pull", pull, sizeof(pull)))
        apply_pull(pull);
    vTaskDelay(1);
    uint32_t in = read_in();
    char buf[400];
    int len = snprintf(buf, sizeof(buf), "{\"ok\":true,\"raw\":%lu,\"ch\":{", (unsigned long)in);
    for (int i = 0; i < N_CH; i++)
        len += snprintf(buf + len, sizeof(buf) - len, "%s\"%s\":%lu", i ? "," : "", ch_name[i], (unsigned long)((in >> i) & 1));
    snprintf(buf + len, sizeof(buf) - len, "}}\n");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, buf);
    return ESP_OK;
}

// GET /channels: mapa de canais
static esp_err_t channels_handler(httpd_req_t *req) {
    char buf[600];
    int len = snprintf(buf, sizeof(buf), "{\"ok\":true,\"cpu_hz\":%u,\"max_ms\":%d,\"channels\":[", CPU_HZ, CAP_MAX_MS);
    for (int i = 0; i < N_CH; i++)
        len += snprintf(buf + len, sizeof(buf) - len, "%s{\"ch\":%d,\"name\":\"%s\",\"gpio\":%d,\"header_pin\":%d}",
                        i ? "," : "", i, ch_name[i], ch_gpio[i], ch_header_pin[i]);
    snprintf(buf + len, sizeof(buf) - len, "]}\n");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, buf);
    return ESP_OK;
}

// GET /capture?ms=100&trigger=IO10&edge=fall|rise|any&timeout_ms=10000&pull=up|down|none&pins=IO10,IO11
// Resposta: CSV no formato gpio_edges v1 (o mesmo do projeto do Flipper), com cpu_hz=240000000.
static esp_err_t capture_handler(httpd_req_t *req) {
    char q[200] = "", tmp[64];
    httpd_req_get_url_query_str(req, q, sizeof(q));
    int ms = 100, timeout_ms = 10000;
    char pull[8] = "none", edge[8] = "any", pins[64] = "";
    int trig = -1;
    if (qparam(q, "ms", tmp, sizeof(tmp))) ms = atoi(tmp);
    if (qparam(q, "timeout_ms", tmp, sizeof(tmp))) timeout_ms = atoi(tmp);
    qparam(q, "pull", pull, sizeof(pull));
    qparam(q, "edge", edge, sizeof(edge));
    qparam(q, "pins", pins, sizeof(pins));
    if (qparam(q, "trigger", tmp, sizeof(tmp)) && tmp[0]) {
        trig = ch_index(tmp);
        if (trig < 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "trigger: canal invalido"); return ESP_OK; }
    }
    if (ms < 1 || ms > CAP_MAX_MS) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ms fora de 1..2000"); return ESP_OK; }
    timeout_ms = MAX(1, MIN(timeout_ms, TRIG_MAX_TIMEOUT_MS));
    uint8_t mask = 0;
    if (pins[0]) {
        char *save = NULL;
        for (char *p = strtok_r(pins, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
            int i = ch_index(p);
            if (i < 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "pins: canal invalido"); return ESP_OK; }
            mask |= 1 << i;
        }
    } else mask = 0xFF;
    if (busy_check && busy_check()) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "ocupado (OTA)"); return ESP_OK; }
    if (xSemaphoreTake(cap_lock, 0) != pdTRUE) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "outra captura em andamento"); return ESP_OK; }

    // Buffer: o maior bloco livre de RAM interna, deixando folga para Wi-Fi e HTTP
    size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    size_t budget = largest > 40 * 1024 ? largest - 32 * 1024 : 0;
    uint32_t max_edges = budget / 5;
    if (max_edges > 30000) max_edges = 30000;
    if (max_edges < 256) { xSemaphoreGive(cap_lock); httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "sem memoria"); return ESP_OK; }
    uint32_t *tbuf = heap_caps_malloc(max_edges * 4, MALLOC_CAP_32BIT | MALLOC_CAP_INTERNAL);
    uint8_t *vbuf = heap_caps_malloc(max_edges, MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    if (!tbuf || !vbuf) {
        free(tbuf); free(vbuf); xSemaphoreGive(cap_lock);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "sem memoria"); return ESP_OK;
    }

    apply_pull(pull);
    vTaskDelay(pdMS_TO_TICKS(2));  // pull assentar
    cap.n = 0; cap.overflow = 0; cap.max_gap = 0; cap.loops = 0; cap.final = 0;
    cap.t = tbuf; cap.v = vbuf; cap.max_edges = max_edges;
    cap.win_cycles = (uint32_t)ms * (CPU_HZ / 1000);
    cap.trig_ch = trig;
    cap.done = false;
    xSemaphoreTake(cap.done_sem, 0);
    const char *status = "ok";
    int64_t t_arm = esp_timer_get_time();
    int64_t waited_us = 0;

    if (trig < 0) {
        uint32_t ps = XTOS_SET_INTLEVEL(XCHAL_EXCM_LEVEL);
        cap.initial = read_in();
        capture_loop(cap.initial);
        XTOS_RESTORE_INTLEVEL(ps);
        cap.done = true;
    } else {
        gpio_int_type_t it = strcmp(edge, "rise") == 0 ? GPIO_INTR_POSEDGE
                           : strcmp(edge, "fall") == 0 ? GPIO_INTR_NEGEDGE : GPIO_INTR_ANYEDGE;
        cap.initial = read_in();
        gpio_isr_handler_add(ch_gpio[trig], trigger_isr, NULL);
        gpio_set_intr_type(ch_gpio[trig], it);
        gpio_intr_enable(ch_gpio[trig]);
        if (xSemaphoreTake(cap.done_sem, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
            gpio_set_intr_type(ch_gpio[trig], GPIO_INTR_DISABLE);
            if (!cap.done) { cap.done = true; status = "timeout"; }
        }
        gpio_intr_disable(ch_gpio[trig]);
        gpio_isr_handler_remove(ch_gpio[trig]);
        waited_us = esp_timer_get_time() - t_arm;
    }
    if (cap.overflow) status = "overflow";

    // CSV
    httpd_resp_set_type(req, "text/csv");
    char line[256];
    int len = snprintf(line, sizeof(line), "# gpio_edges v1 mode=s2dedic cpu_hz=%u ms=%d pull=%s trigger=%s edge=%s pins=",
                       CPU_HZ, ms, pull, trig >= 0 ? ch_name[trig] : "none", edge);
    bool first = true;
    for (int i = 0; i < N_CH; i++)
        if (mask & (1 << i)) { len += snprintf(line + len, sizeof(line) - len, "%s%s", first ? "" : ",", ch_name[i]); first = false; }
    len += snprintf(line + len, sizeof(line) - len, "\n# initial");
    for (int i = 0; i < N_CH; i++)
        if (mask & (1 << i)) len += snprintf(line + len, sizeof(line) - len, " %s=%d", ch_name[i], (cap.initial >> i) & 1);
    len += snprintf(line + len, sizeof(line) - len, "\ncycles,pin,level\n");
    httpd_resp_send_chunk(req, line, len);

    static char out[1460];
    int olen = 0;
    uint32_t edges_out = 0;
    uint8_t prev = cap.initial;
    for (uint32_t k = 0; k < cap.n; k++) {
        uint8_t ch = (cap.v[k] ^ prev) & mask;
        for (int i = 0; ch && i < N_CH; i++) {
            if (!(ch & (1 << i))) continue;
            if (olen > (int)sizeof(out) - 40) { httpd_resp_send_chunk(req, out, olen); olen = 0; }
            olen += snprintf(out + olen, sizeof(out) - olen, "%lu,%s,%d\n", (unsigned long)cap.t[k], ch_name[i], (cap.v[k] >> i) & 1);
            edges_out++;
        }
        prev = cap.v[k];
    }
    if (olen) httpd_resp_send_chunk(req, out, olen);
    len = snprintf(line, sizeof(line),
                   "# end edges=%lu overflow=%lu max_gap_cycles=%lu status=%s loops=%lu max_edges=%lu wait_ms=%lld err=\n",
                   (unsigned long)edges_out, (unsigned long)cap.overflow, (unsigned long)cap.max_gap, status,
                   (unsigned long)cap.loops, (unsigned long)max_edges, waited_us / 1000);
    httpd_resp_send_chunk(req, line, len);
    httpd_resp_send_chunk(req, NULL, 0);
    ESP_LOGI(TAG, "captura %s: %lu bordas, %lu voltas, gap max %lu ciclos", status, (unsigned long)edges_out,
             (unsigned long)cap.loops, (unsigned long)cap.max_gap);
    free(tbuf);
    free(vbuf);
    xSemaphoreGive(cap_lock);
    return ESP_OK;
}

// POST /gen?pin=IO10&hz=1000&duty=50 (hz=0 desliga): gerador de teste (LEDC) num canal, com a entrada
// ligada no mesmo pino: o analisador se mede sozinho, sem nada externo. NÃO usar com sinal externo
// ligado ao pino (curto entre saídas).
static int gen_pin = -1;
static esp_err_t gen_handler(httpd_req_t *req) {
    if (auth_check && !auth_check(req)) return ESP_OK;
    char q[100] = "", tmp[32] = "";
    httpd_req_get_url_query_str(req, q, sizeof(q));
    int hz = qparam(q, "hz", tmp, sizeof(tmp)) ? atoi(tmp) : 0;
    int duty = qparam(q, "duty", tmp, sizeof(tmp)) ? atoi(tmp) : 50;
    int ch = qparam(q, "pin", tmp, sizeof(tmp)) ? ch_index(tmp) : 0;
    if (ch < 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "pin invalido"); return ESP_OK; }
    if (gen_pin >= 0) {
        ledc_stop(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, 0);
        gpio_reset_pin(gen_pin);
        gpio_set_direction(gen_pin, GPIO_MODE_INPUT);
        // devolve o pino ao bundle (o reset desfaz a ligação de entrada da matriz)
        dedic_gpio_del_bundle(bundle);
        dedic_gpio_bundle_config_t cfg = { .gpio_array = ch_gpio, .array_size = N_CH, .flags = { .in_en = 1 } };
        dedic_gpio_new_bundle(&cfg, &bundle);
        gen_pin = -1;
    }
    char buf[160];
    if (hz <= 0) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":true,\"gen\":\"off\"}\n");
        return ESP_OK;
    }
    duty = MAX(1, MIN(duty, 99));
    ledc_timer_config_t tc = { .speed_mode = LEDC_LOW_SPEED_MODE, .timer_num = LEDC_TIMER_0,
                               .duty_resolution = LEDC_TIMER_8_BIT, .freq_hz = hz, .clk_cfg = LEDC_AUTO_CLK };
    if (hz > 150000) tc.duty_resolution = LEDC_TIMER_4_BIT;
    esp_err_t err = ledc_timer_config(&tc);
    if (err != ESP_OK) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "frequencia invalida"); return ESP_OK; }
    uint32_t full = 1u << tc.duty_resolution;
    ledc_channel_config_t cc = { .gpio_num = ch_gpio[ch], .speed_mode = LEDC_LOW_SPEED_MODE, .channel = LEDC_CHANNEL_0,
                                 .timer_sel = LEDC_TIMER_0, .duty = full * duty / 100, .hpoint = 0 };
    ledc_channel_config(&cc);
    gpio_set_direction(ch_gpio[ch], GPIO_MODE_INPUT_OUTPUT);  // mantém a entrada do bundle viva
    gen_pin = ch_gpio[ch];
    snprintf(buf, sizeof(buf), "{\"ok\":true,\"gen\":\"%s\",\"hz\":%lu,\"duty\":%d}\n", ch_name[ch],
             (unsigned long)ledc_get_freq(LEDC_LOW_SPEED_MODE, LEDC_TIMER_0), duty);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, buf);
    return ESP_OK;
}

void capture_register(httpd_handle_t server) {
    const httpd_uri_t uris[] = {
        { .uri = "/capture",  .method = HTTP_GET,  .handler = capture_handler },
        { .uri = "/levels",   .method = HTTP_GET,  .handler = levels_handler },
        { .uri = "/channels", .method = HTTP_GET,  .handler = channels_handler },
        { .uri = "/gen",      .method = HTTP_POST, .handler = gen_handler },
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) httpd_register_uri_handler(server, &uris[i]);
}
