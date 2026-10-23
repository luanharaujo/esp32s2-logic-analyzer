// Captura de bordas nos 8 canais sem solda da devboard.
//
// Método: os 8 GPIOs viram um "bundle" de GPIO dedicado do ESP32-S2 (instrução get_gpio_in, 1 ciclo,
// lê os 8 de uma vez). Um laço em IRAM, com interrupções mascaradas, lê os pinos e o contador de ciclos
// (240 MHz, 4,17 ns) e grava só as mudanças. Cada volta do laço leva poucos ciclos (o max_gap_cycles do
// CSV diz quanto), então a resolução é de dezenas de ns, bem melhor que 1 µs.
// Trigger (padrão tmode=poll): o mesmo laço espera a borda em fatias de 100 ms com interrupções mascaradas
// (latência ~0,1 µs; ~1% do tempo cego, nas pausas de 1 ms para o Wi-Fi). tmode=isr: interrupção de GPIO,
// Wi-Fi livre na espera, mas ~1 a 2 µs de latência. Sem trigger, a captura começa na hora.
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
#include "driver/rmt.h"
#include "hal/cpu_ll.h"
#include "xtensa/core-macros.h"
#include "capture.h"

static const char *TAG = "CAP";

#define CPU_HZ 240000000u
#define N_CH 8
#define CAP_MAX_MS 2000
#define TRIG_MAX_TIMEOUT_MS 60000
#define POLL_SLICE_MS 100

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

// O laço quente. Chamado com interrupções mascaradas. start: ciclo do t=0. first_in >= 0: grava esse
// valor como a primeira borda em t=0 (a borda do trigger detectada pelo laço de espera).
static void IRAM_ATTR __attribute__((noinline)) capture_loop(uint32_t last, uint32_t start, int first_in) {
    uint32_t *t = cap.t;
    uint8_t *v = cap.v;
    uint32_t n = 0, max_edges = cap.max_edges, win = cap.win_cycles, max_gap = 0, loops = 0;
    if (first_in >= 0 && (uint32_t)first_in != last) {
        t[0] = 0;
        v[0] = (uint8_t)first_in;
        n = 1;
        last = (uint32_t)first_in;
    }
    uint32_t prev = XTHAL_GET_CCOUNT();
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

// Espera o trigger lendo os pinos no mesmo laço apertado (latência de ~0,1 µs), por no máximo slice
// ciclos. Devolve 0 se não veio; 1 se veio (em *t_trig, com *in_trig = valor depois da borda e *plast =
// valor antes); 2 se já veio na 1a leitura (a borda pode ter ocorrido na pausa entre fatias).
enum { EDGE_ANY = 0, EDGE_RISE = 1, EDGE_FALL = 2 };
static int IRAM_ATTR __attribute__((noinline)) wait_trigger(uint32_t *plast, uint32_t bit, int edge, uint32_t slice, uint32_t *t_trig,
                                  uint32_t *in_trig) {
    uint32_t last = *plast, t0 = XTHAL_GET_CCOUNT();
    bool first = true;
    while (1) {
        uint32_t now = XTHAL_GET_CCOUNT();
        uint32_t in = read_in();
        if ((in ^ last) & bit) {
            bool rise = (in & bit) != 0;
            if (edge == EDGE_ANY || (edge == EDGE_RISE && rise) || (edge == EDGE_FALL && !rise)) {
                *t_trig = now;
                *in_trig = in;
                *plast = last;
                return first ? 2 : 1;
            }
        }
        last = in;
        first = false;
        if (now - t0 > slice) { *plast = last; return 0; }
    }
}

// Desliga a interrupção do pino direto no registrador (seguro dentro da ISR)
static inline void IRAM_ATTR gpio_ll_intr_disable_irq(int gpio) { GPIO.pin[gpio].int_type = 0; }

static void IRAM_ATTR trigger_isr(void *arg) {
    if (cap.done) return;
    gpio_ll_intr_disable_irq(ch_gpio[cap.trig_ch]);
    uint32_t ps = XTOS_SET_INTLEVEL(XCHAL_EXCM_LEVEL);
    capture_loop(cap.initial, XTHAL_GET_CCOUNT(), -1);
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
    char q[240] = "", tmp[64];
    httpd_req_get_url_query_str(req, q, sizeof(q));
    int ms = 100, timeout_ms = 10000;
    char pull[8] = "none", edge[8] = "any", pins[64] = "", tmode[8] = "poll";
    int trig = -1;
    if (qparam(q, "ms", tmp, sizeof(tmp))) ms = atoi(tmp);
    if (qparam(q, "timeout_ms", tmp, sizeof(tmp))) timeout_ms = atoi(tmp);
    qparam(q, "pull", pull, sizeof(pull));
    qparam(q, "edge", edge, sizeof(edge));
    qparam(q, "pins", pins, sizeof(pins));
    qparam(q, "tmode", tmode, sizeof(tmode));
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

    // Buffer: o maior bloco livre de RAM interna, deixando folga para Wi-Fi e HTTP. Se não couber
    // (placa WROVER: Wi-Fi e cache da PSRAM comem a RAM interna), usa a PSRAM.
    size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    size_t budget = largest > 40 * 1024 ? largest - 32 * 1024 : 0;
    uint32_t max_edges = budget / 5;
    if (max_edges > 30000) max_edges = 30000;
    uint32_t caps_extra = MALLOC_CAP_INTERNAL;
    if (max_edges < 4096 && heap_caps_get_total_size(MALLOC_CAP_SPIRAM) > 0) {
        size_t pl = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
        uint32_t pe = pl > 64 * 1024 ? (pl - 32 * 1024) / 5 : 0;
        if (pe > 200000) pe = 200000;
        if (pe > max_edges) { max_edges = pe; caps_extra = MALLOC_CAP_SPIRAM; }
    }
    const char *bufkind = caps_extra == MALLOC_CAP_SPIRAM ? "psram" : "internal";
    ESP_LOGI(TAG, "captura: buffer %s, %lu bordas (int livre %u, maior bloco %u)", bufkind,
             (unsigned long)max_edges, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)largest);
    if (max_edges < 256) { xSemaphoreGive(cap_lock); httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "sem memoria"); return ESP_OK; }
    uint32_t *tbuf = heap_caps_malloc(max_edges * 4, MALLOC_CAP_32BIT | caps_extra);
    uint8_t *vbuf = heap_caps_malloc(max_edges, MALLOC_CAP_8BIT | caps_extra);
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

    int edge_code = strcmp(edge, "rise") == 0 ? EDGE_RISE : strcmp(edge, "fall") == 0 ? EDGE_FALL : EDGE_ANY;
    if (trig < 0) {
        uint32_t ps = XTOS_SET_INTLEVEL(XCHAL_EXCM_LEVEL);
        cap.initial = read_in();
        capture_loop(cap.initial, XTHAL_GET_CCOUNT(), -1);
        XTOS_RESTORE_INTLEVEL(ps);
        cap.done = true;
    } else if (strcmp(tmode, "isr") == 0) {
        // Trigger por interrupção: Wi-Fi livre durante a espera, mas ~1 a 2 µs de latência (pode perder
        // pulsos de bounce mais curtos que isso logo no começo)
        gpio_int_type_t it = edge_code == EDGE_RISE ? GPIO_INTR_POSEDGE : edge_code == EDGE_FALL ? GPIO_INTR_NEGEDGE : GPIO_INTR_ANYEDGE;
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
    } else {
        // Trigger por varredura (padrão): espera no laço apertado em fatias de POLL_SLICE_MS com as
        // interrupções mascaradas, soltando ~1 ms entre fatias para o Wi-Fi respirar. Latência ~0,1 µs.
        // Se a borda cair na pausa, é vista no começo da fatia seguinte (status=trigger_in_gap).
        uint32_t last = read_in(), t_trig = 0, in_trig = 0;
        cap.initial = last;
        int64_t deadline = t_arm + (int64_t)timeout_ms * 1000;
        int r = 0;
        while (esp_timer_get_time() < deadline) {
            uint32_t ps = XTOS_SET_INTLEVEL(XCHAL_EXCM_LEVEL);
            r = wait_trigger(&last, 1u << trig, edge_code, POLL_SLICE_MS * (CPU_HZ / 1000), &t_trig, &in_trig);
            if (r) {
                cap.initial = last;
                capture_loop(last, t_trig, (int)in_trig);
            }
            XTOS_RESTORE_INTLEVEL(ps);
            if (r) break;
            vTaskDelay(1);
        }
        if (!r) status = "timeout";
        else if (r == 2) status = "trigger_in_gap";
        cap.done = true;
    }
    waited_us = esp_timer_get_time() - t_arm;
    if (cap.overflow) status = "overflow";

    // CSV
    httpd_resp_set_type(req, "text/csv");
    char line[256];
    int len = snprintf(line, sizeof(line), "# gpio_edges v1 mode=s2dedic cpu_hz=%u ms=%d pull=%s trigger=%s edge=%s tmode=%s pins=",
                       CPU_HZ, ms, pull, trig >= 0 ? ch_name[trig] : "none", edge, tmode);
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
                   "# end edges=%lu overflow=%lu max_gap_cycles=%lu status=%s loops=%lu max_edges=%lu buf=%s wait_ms=%lld err=\n",
                   (unsigned long)edges_out, (unsigned long)cap.overflow, (unsigned long)cap.max_gap, status,
                   (unsigned long)cap.loops, (unsigned long)max_edges, bufkind, waited_us / 1000);
    httpd_resp_send_chunk(req, line, len);
    httpd_resp_send_chunk(req, NULL, 0);
    ESP_LOGI(TAG, "captura %s: %lu bordas, %lu voltas, gap max %lu ciclos", status, (unsigned long)edges_out,
             (unsigned long)cap.loops, (unsigned long)cap.max_gap);
    free(tbuf);
    free(vbuf);
    xSemaphoreGive(cap_lock);
    return ESP_OK;
}

// POST /gen: gerador de teste num canal, com a entrada ligada no mesmo pino, para o analisador se
// medir sozinho, sem nada externo. NÃO usar com sinal externo ligado ao pino (curto entre saídas).
//   /gen?pin=IO10&hz=1000&duty=50              onda quadrada contínua (LEDC); hz=0 desliga tudo
//   /gen?pin=IO10&mode=bounce&delay_ms=1000    uma rajada que imita um botão com bounce (RMT, 1 µs
//                                              exato), disparada delay_ms depois (para dar tempo de
//                                              armar um /capture com trigger)
// Padrão do bounce (µs, a partir do repouso em 1): ver bounce_pattern.
static int gen_pin = -1;
static enum { GEN_OFF, GEN_LEDC, GEN_RMT } gen_mode = GEN_OFF;
static esp_timer_handle_t gen_timer = NULL;
static rmt_item32_t bounce_items[24];
static int bounce_n = 0;
// nível, duração em µs. Pressão (6 bordas de bounce, depois 20 ms em 0), soltura (5 bordas, volta a 1)
static const int16_t bounce_pattern[][2] = {
    {0, 3}, {1, 5}, {0, 12}, {1, 8}, {0, 40}, {1, 25}, {0, 20000},
    {1, 4}, {0, 6}, {1, 15}, {0, 10}, {1, 60},
};

static void gen_release(void) {
    if (gen_mode == GEN_LEDC) ledc_stop(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, 0);
    if (gen_mode == GEN_RMT) rmt_driver_uninstall(RMT_CHANNEL_0);
    if (gen_pin >= 0) {
        gpio_reset_pin(gen_pin);
        gpio_set_direction(gen_pin, GPIO_MODE_INPUT);
        // devolve o pino ao bundle (o reset desfaz a ligação de entrada da matriz)
        dedic_gpio_del_bundle(bundle);
        dedic_gpio_bundle_config_t cfg = { .gpio_array = ch_gpio, .array_size = N_CH, .flags = { .in_en = 1 } };
        dedic_gpio_new_bundle(&cfg, &bundle);
    }
    gen_pin = -1;
    gen_mode = GEN_OFF;
}

static void gen_fire(void *arg) {
    if (gen_mode == GEN_RMT) rmt_write_items(RMT_CHANNEL_0, bounce_items, bounce_n, false);
}

static esp_err_t gen_handler(httpd_req_t *req) {
    if (auth_check && !auth_check(req)) return ESP_OK;
    char q[120] = "", tmp[32] = "", mode[12] = "square";
    httpd_req_get_url_query_str(req, q, sizeof(q));
    int hz = qparam(q, "hz", tmp, sizeof(tmp)) ? atoi(tmp) : 0;
    int duty = qparam(q, "duty", tmp, sizeof(tmp)) ? atoi(tmp) : 50;
    int delay_ms = qparam(q, "delay_ms", tmp, sizeof(tmp)) ? atoi(tmp) : 500;
    int ch = qparam(q, "pin", tmp, sizeof(tmp)) ? ch_index(tmp) : 0;
    qparam(q, "mode", mode, sizeof(mode));
    if (ch < 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "pin invalido"); return ESP_OK; }
    if (gen_timer) esp_timer_stop(gen_timer);
    gen_release();
    char buf[200];
    httpd_resp_set_type(req, "application/json");
    if (strcmp(mode, "bounce") == 0) {
        rmt_config_t rc = RMT_DEFAULT_CONFIG_TX(ch_gpio[ch], RMT_CHANNEL_0);
        rc.clk_div = 80;  // APB 80 MHz / 80 = 1 µs por tick
        rc.tx_config.idle_output_en = true;
        rc.tx_config.idle_level = RMT_IDLE_LEVEL_HIGH;
        rc.tx_config.carrier_en = false;
        if (rmt_config(&rc) != ESP_OK || rmt_driver_install(RMT_CHANNEL_0, 0, 0) != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "rmt"); return ESP_OK;
        }
        int np = sizeof(bounce_pattern) / sizeof(bounce_pattern[0]);
        bounce_n = 0;
        for (int i = 0; i < np; i += 2) {
            rmt_item32_t it = { .level0 = bounce_pattern[i][0], .duration0 = bounce_pattern[i][1] };
            if (i + 1 < np) { it.level1 = bounce_pattern[i + 1][0]; it.duration1 = bounce_pattern[i + 1][1]; }
            else { it.level1 = 1; it.duration1 = 0; }
            bounce_items[bounce_n++] = it;
        }
        if (np % 2 == 0) bounce_items[bounce_n++] = (rmt_item32_t){ .level0 = 1, .duration0 = 0, .level1 = 1, .duration1 = 0 };
        gpio_set_direction(ch_gpio[ch], GPIO_MODE_INPUT_OUTPUT);  // mantém a entrada do bundle viva
        gen_pin = ch_gpio[ch];
        gen_mode = GEN_RMT;
        if (!gen_timer) {
            esp_timer_create_args_t ta = { .callback = gen_fire, .name = "gen" };
            esp_timer_create(&ta, &gen_timer);
        }
        delay_ms = MAX(0, MIN(delay_ms, 60000));
        esp_timer_start_once(gen_timer, (uint64_t)delay_ms * 1000 + 1);
        int len = snprintf(buf, sizeof(buf), "{\"ok\":true,\"gen\":\"%s\",\"mode\":\"bounce\",\"delay_ms\":%d,\"pattern_us\":[",
                           ch_name[ch], delay_ms);
        for (int i = 0; i < np && len < (int)sizeof(buf) - 12; i++)
            len += snprintf(buf + len, sizeof(buf) - len, "%s%d", i ? "," : "", bounce_pattern[i][1]);
        snprintf(buf + len, sizeof(buf) - len, "]}\n");
        httpd_resp_sendstr(req, buf);
        return ESP_OK;
    }
    if (hz <= 0) { httpd_resp_sendstr(req, "{\"ok\":true,\"gen\":\"off\"}\n"); return ESP_OK; }
    duty = MAX(1, MIN(duty, 99));
    ledc_timer_config_t tc = { .speed_mode = LEDC_LOW_SPEED_MODE, .timer_num = LEDC_TIMER_0,
                               .duty_resolution = LEDC_TIMER_8_BIT, .freq_hz = hz, .clk_cfg = LEDC_AUTO_CLK };
    if (hz > 150000) tc.duty_resolution = LEDC_TIMER_4_BIT;
    if (ledc_timer_config(&tc) != ESP_OK) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "frequencia invalida"); return ESP_OK; }
    uint32_t full = 1u << tc.duty_resolution;
    ledc_channel_config_t cc = { .gpio_num = ch_gpio[ch], .speed_mode = LEDC_LOW_SPEED_MODE, .channel = LEDC_CHANNEL_0,
                                 .timer_sel = LEDC_TIMER_0, .duty = full * duty / 100, .hpoint = 0 };
    ledc_channel_config(&cc);
    gpio_set_direction(ch_gpio[ch], GPIO_MODE_INPUT_OUTPUT);
    gen_pin = ch_gpio[ch];
    gen_mode = GEN_LEDC;
    snprintf(buf, sizeof(buf), "{\"ok\":true,\"gen\":\"%s\",\"mode\":\"square\",\"hz\":%lu,\"duty\":%d}\n", ch_name[ch],
             (unsigned long)ledc_get_freq(LEDC_LOW_SPEED_MODE, LEDC_TIMER_0), duty);
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
