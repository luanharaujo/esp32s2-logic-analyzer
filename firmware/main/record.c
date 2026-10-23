// Gravação contínua para testes de bancada (/record): uma janela longa (até REC_MAX_S) sem rearmar.
//
// Diferente do /capture (laço com interrupções mascaradas, no máx. 2 s), aqui o laço de varredura roda
// numa tarefa de prioridade 1 com as interrupções LIGADAS: Wi-Fi, HTTP e watchdog seguem vivos, e o
// cliente consulta o progresso (/record/status) enquanto grava. Preço: quando uma interrupção ou
// tarefa mais alta toma a CPU, o laço para por alguns µs; uma borda nesse intervalo é gravada atrasada
// e um pulso mais curto que a pausa se perde. O CSV traz max_gap_cycles e gaps_over_2us para medir isso.
// A tarefa ociosa fica fora do Task Watchdog durante a gravação (o laço não a deixa rodar).
//
// Tempo: contador de ciclos estendido para 64 bits; cada borda guarda (ciclos >> 4) em 32 bits
// (66,7 ns, até 286 s). Eventos (rajadas separadas por settle_ms) são contados ao vivo.
// Buffer cheio: para de guardar bordas, mas continua contando e guarda um resumo por rajada
// (início, fim, bordas) para não perder os eventos.
// ADC (opcional, adc_pin): modo contínuo por DMA numa tarefa própria; guarda uma janela analógica por
// evento (adc_pre_ms antes, adc_post_ms depois), alinhada pelo relógio do sistema (aprox. ±0,2 ms).
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "hal/cpu_ll.h"
#include "xtensa/core-macros.h"
#include "capture.h"

static const char *TAG = "REC";

#define CPU_HZ 240000000u
#define N_CH 8
#define REC_MAX_S 280
#define REC_SHIFT 4                 // ciclos >> 4 = 66,7 ns por unidade
#define REC_MAX_EVENTS 2000
#define REC_MAX_BURSTS 20000
#define REC_ADC_MAX_EVENTS 64
#define REC_ADC_HIST 20000

typedef struct { uint32_t t0, t1, n; uint8_t final; } burst_t;
typedef struct { uint32_t ev; uint32_t start; uint32_t n; } adc_ev_t;  // índice do evento, 1a amostra, quantas

typedef struct {
    volatile int state;       // 0 livre, 1 gravando, 2 pronto (dados esperando /record/data)
    volatile bool stop;
    uint32_t s, settle_ticks;
    uint8_t mask, initial, final;
    char pins[64], pull[8];
    uint32_t *t; uint8_t *v; uint32_t n, max;
    volatile uint32_t total;  // bordas vistas (inclusive depois de cheio)
    uint32_t *ev_t;            // PSRAM (a RAM interna é pouca)
    volatile uint32_t n_ev;
    burst_t *bursts; uint32_t n_bursts;
    uint32_t max_gap, gaps_over, gaps_10us, gaps_100us, gaps_1ms;
    uint64_t max_gap_at;
    uint64_t loops;
    volatile uint64_t now_cyc;  // ciclos desde o início (lido pela tarefa do ADC)
    int64_t t0_us;            // esp_timer no início
    int64_t start_wall_us;
    volatile int64_t elapsed_us;
    // ADC
    bool adc;
    char adc_pin[12];
    int adc_rate;
    uint32_t adc_period_cycles;
    uint32_t pre_ms, post_ms;
    uint16_t *hist; uint32_t *hist_t;  // histórico circular: amostra e tempo (ciclos >> 4)
    uint32_t hist_n;                   // amostras já escritas (posição = hist_n % REC_ADC_HIST)
    uint16_t *aev; uint32_t *aev_t; uint32_t aev_n, aev_max;
    adc_ev_t *adc_ev; uint32_t n_adc_ev;  // PSRAM
    uint32_t adc_invalid, adc_lost_events;
    volatile bool adc_done;
    TaskHandle_t task;
} rec_t;
static rec_t rec;
static SemaphoreHandle_t rec_done_sem = NULL;

static inline uint32_t IRAM_ATTR rd_in(void) { return cpu_ll_read_dedic_gpio_in() & 0xFF; }

static void IRAM_ATTR __attribute__((noinline)) rec_loop(uint64_t end_cyc) {
    uint32_t *t = rec.t;
    uint8_t *v = rec.v;
    uint32_t n = 0, max = rec.max, mask = rec.mask, settle = rec.settle_ticks;
    uint32_t max_gap = 0, gaps_over = 0, g10 = 0, g100 = 0, g1ms = 0, total = 0, n_ev = 0, n_b = 0;
    uint64_t max_at = 0;
    uint64_t cyc = 0, loops = 0;
    uint32_t last = rd_in() & mask, last_edge = 0;
    bool any_edge = false;
    rec.initial = (uint8_t)last;
    uint32_t prev = XTHAL_GET_CCOUNT();
    while (!rec.stop) {
        uint32_t now = XTHAL_GET_CCOUNT();
        uint32_t in = rd_in() & mask;
        uint32_t d = now - prev;
        prev = now;
        cyc += d;
        if (d > 480) {  // > 2 µs sem olhar o pino
            gaps_over++;
            if (d > 2400) { g10++; if (d > 24000) { g100++; if (d > 240000) g1ms++; } }
            if (d > max_gap) { max_gap = d; max_at = cyc; }
        }
        if (in != last) {
            uint32_t tk = (uint32_t)(cyc >> REC_SHIFT);
            bool new_ev = !any_edge || tk - last_edge > settle;
            if (new_ev && n_ev < REC_MAX_EVENTS) { rec.ev_t[n_ev++] = tk; rec.n_ev = n_ev; }
            if (n < max) {
                t[n] = tk; v[n] = (uint8_t)in; n++;
            } else if (rec.bursts) {
                if (new_ev || n_b == 0) {
                    if (n_b < REC_MAX_BURSTS) { rec.bursts[n_b].t0 = tk; rec.bursts[n_b].n = 0; n_b++; }
                }
                if (n_b) { burst_t *b = &rec.bursts[n_b - 1]; b->t1 = tk; b->n++; b->final = (uint8_t)in; }
            }
            total++;
            rec.total = total;
            last = in;
            last_edge = tk;
            any_edge = true;
        }
        if ((++loops & 0x3FF) == 0) {
            rec.now_cyc = cyc;
            if (cyc >= end_cyc) break;
        }
    }
    rec.now_cyc = cyc;
    rec.n = n; rec.n_bursts = n_b; rec.max_gap = max_gap; rec.gaps_over = gaps_over; rec.loops = loops;
    rec.gaps_10us = g10; rec.gaps_100us = g100; rec.gaps_1ms = g1ms; rec.max_gap_at = max_at;
    rec.final = (uint8_t)last;
}

// Tarefa do ADC: lê o anel do DMA, mantém um histórico com tempo e recorta uma janela por evento
static void rec_adc_task(void *pv) {
    uint16_t *buf = heap_caps_malloc(512 * 2, MALLOC_CAP_SPIRAM);  // RAM interna é pouca
    // liga e desliga o DMA nesta mesma tarefa: adc_digi_start/stop pegam e soltam um mutex do ADC1, que
    // só pode ser solto pela tarefa que pegou (senão assert em xQueueGenericSend -> panic, visto no 0.4.1)
    while (!rec.t0_us) vTaskDelay(1);  // espera o laço digital marcar o t0
    uint32_t t0;
    adc_bg_restart(&t0);
    uint32_t done_ev = 0;
    const uint32_t per_ticks16 = rec.adc_period_cycles;  // em ciclos
    while (1) {
        bool running = rec.state == 1;
        uint32_t inv = 0;
        uint32_t m = adc_bg_read(buf, 512, 20, &inv);
        rec.adc_invalid += inv;
        if (m) {
            // a última amostra do bloco acabou de sair: tempo = agora; as anteriores, um período cada
            uint64_t now_cyc = (uint64_t)(esp_timer_get_time() - rec.t0_us) * (CPU_HZ / 1000000);
            for (uint32_t i = 0; i < m; i++) {
                uint32_t pos = rec.hist_n % REC_ADC_HIST;
                uint64_t c = now_cyc - (uint64_t)(m - 1 - i) * per_ticks16;
                rec.hist[pos] = buf[i];
                rec.hist_t[pos] = (uint32_t)(c >> REC_SHIFT);
                rec.hist_n++;
            }
        }
        // recorta as janelas dos eventos cujo "depois" já passou
        uint32_t now_tk = (uint32_t)(((uint64_t)(esp_timer_get_time() - rec.t0_us) * (CPU_HZ / 1000000)) >> REC_SHIFT);
        uint32_t pre_tk = (uint32_t)((uint64_t)rec.pre_ms * (CPU_HZ / 1000) >> REC_SHIFT);
        uint32_t post_tk = (uint32_t)((uint64_t)rec.post_ms * (CPU_HZ / 1000) >> REC_SHIFT);
        while (done_ev < rec.n_ev && (now_tk > rec.ev_t[done_ev] + post_tk + 100000 || !running)) {
            uint32_t te = rec.ev_t[done_ev];
            // pula eventos que caem dentro da janela do anterior (já cobertos)
            if (rec.n_adc_ev && te <= rec.ev_t[rec.adc_ev[rec.n_adc_ev - 1].ev] + post_tk) { done_ev++; continue; }
            if (rec.n_adc_ev >= REC_ADC_MAX_EVENTS) { rec.adc_lost_events++; done_ev++; continue; }
            uint32_t lo = te > pre_tk ? te - pre_tk : 0, hi = te + post_tk;
            uint32_t first = rec.hist_n > REC_ADC_HIST ? rec.hist_n - REC_ADC_HIST : 0;
            uint32_t start = rec.aev_n, k = 0;
            for (uint32_t j = first; j < rec.hist_n && rec.aev_n < rec.aev_max; j++) {
                uint32_t pos = j % REC_ADC_HIST;
                uint32_t tj = rec.hist_t[pos];
                if (tj >= lo && tj <= hi) { rec.aev[rec.aev_n] = rec.hist[pos]; rec.aev_t[rec.aev_n] = tj; rec.aev_n++; k++; }
            }
            if (k) { rec.adc_ev[rec.n_adc_ev++] = (adc_ev_t){ .ev = done_ev, .start = start, .n = k }; }
            else rec.adc_lost_events++;
            done_ev++;
        }
        if (!running && done_ev >= rec.n_ev) break;
    }
    free(buf);
    adc_bg_close();
    rec.adc_done = true;
    vTaskDelete(NULL);
}

static void rec_task(void *pv) {
    TaskHandle_t idle = xTaskGetIdleTaskHandleForCPU(0);
    esp_task_wdt_delete(idle);  // o laço não deixa a ociosa rodar; volta no fim
    uint64_t end_cyc = (uint64_t)rec.s * CPU_HZ;
    rec.t0_us = esp_timer_get_time();
    rec_loop(end_cyc);
    rec.elapsed_us = esp_timer_get_time() - rec.t0_us;
    esp_task_wdt_add(idle);
    rec.state = 2;  // o ADC termina de recortar as janelas pendentes e sai; só então fecha o driver
    if (rec.adc) {
        while (!rec.adc_done) vTaskDelay(pdMS_TO_TICKS(10));
    }
    ESP_LOGI(TAG, "gravação: %lu bordas (%lu guardadas), %lu eventos, gap max %lu ciclos, %lu pausas > 2 µs",
             (unsigned long)rec.total, (unsigned long)rec.n, (unsigned long)rec.n_ev, (unsigned long)rec.max_gap,
             (unsigned long)rec.gaps_over);
    xSemaphoreGive(rec_done_sem);
    rec.task = NULL;
    vTaskDelete(NULL);
}

static void rec_free(void) {
    free(rec.ev_t); rec.ev_t = NULL;
    free(rec.adc_ev); rec.adc_ev = NULL;
    free(rec.t); free(rec.v); free(rec.bursts); free(rec.hist); free(rec.hist_t); free(rec.aev); free(rec.aev_t);
    rec.t = NULL; rec.v = NULL; rec.bursts = NULL; rec.hist = NULL; rec.hist_t = NULL; rec.aev = NULL; rec.aev_t = NULL;
}

// Descarta uma gravação pronta que ninguém baixou (para /capture e /adc não ficarem travados)
bool record_discard_if_done(void) {
    if (rec.state != 2) return false;
    rec_free();
    rec.state = 0;
    capture_unlock();
    ESP_LOGW(TAG, "gravação não baixada descartada");
    return true;
}

static bool qp(const char *q, const char *k, char *o, size_t n) { return q && httpd_query_key_value(q, k, o, n) == ESP_OK; }

static void reply_json(httpd_req_t *req, const char *s) {
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, s);
}

// POST /record?s=120&pins=IO10&pull=none&settle_ms=5[&adc_pin=IO1&adc_rate=10000&adc_pre_ms=20&adc_post_ms=80]
static esp_err_t record_start_handler(httpd_req_t *req) {
    char q[240] = "", tmp[32];
    httpd_req_get_url_query_str(req, q, sizeof(q));
    if (rec.state == 1) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "ja gravando"); return ESP_OK; }
    record_discard_if_done();
    int s = 60, settle_ms = 5, adc_rate = 10000, pre = 20, post = 80;
    char pins[64] = "IO10", pull[8] = "none", adc_pin[12] = "";
    if (qp(q, "s", tmp, sizeof(tmp))) s = atoi(tmp);
    if (qp(q, "settle_ms", tmp, sizeof(tmp))) settle_ms = atoi(tmp);
    if (qp(q, "adc_rate", tmp, sizeof(tmp))) adc_rate = atoi(tmp);
    if (qp(q, "adc_pre_ms", tmp, sizeof(tmp))) pre = atoi(tmp);
    if (qp(q, "adc_post_ms", tmp, sizeof(tmp))) post = atoi(tmp);
    qp(q, "pins", pins, sizeof(pins));
    qp(q, "pull", pull, sizeof(pull));
    qp(q, "adc_pin", adc_pin, sizeof(adc_pin));
    if (s < 1 || s > REC_MAX_S) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "s fora de 1..280"); return ESP_OK; }
    settle_ms = MAX(1, MIN(settle_ms, 1000));
    pre = MAX(0, MIN(pre, 500)); post = MAX(1, MIN(post, 500));
    uint8_t mask = 0;
    char pcopy[64];
    strlcpy(pcopy, pins, sizeof(pcopy));
    char *save = NULL;
    for (char *p = strtok_r(pcopy, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
        int i = capture_ch_index(p);
        if (i < 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "pins: canal invalido"); return ESP_OK; }
        mask |= 1 << i;
    }
    if (!mask) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "pins vazio"); return ESP_OK; }
    if (capture_is_busy()) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "ocupado (OTA)"); return ESP_OK; }
    if (!capture_lock(0)) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "outra captura em andamento"); return ESP_OK; }

    memset(&rec, 0, sizeof(rec));
    if (!rec_done_sem) rec_done_sem = xSemaphoreCreateBinary();
    xSemaphoreTake(rec_done_sem, 0);
    rec.s = s; rec.mask = mask;
    rec.settle_ticks = (uint32_t)((uint64_t)settle_ms * (CPU_HZ / 1000) >> REC_SHIFT);
    strlcpy(rec.pins, pins, sizeof(rec.pins));
    strlcpy(rec.pull, pull, sizeof(rec.pull));
    // Buffers na PSRAM: bordas (5 bytes cada) com o maior bloco livre menos folga para o ADC
    size_t pl = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    size_t reserve = 300 * 1024 + (adc_pin[0] ? 500 * 1024 : 0);
    uint32_t max = pl > reserve + 64 * 1024 ? (uint32_t)((pl - reserve) / 4) : 0;  // t (4 bytes) num bloco
    max = MIN(max, 250000u);
    rec.t = heap_caps_malloc((size_t)max * 4, MALLOC_CAP_SPIRAM);
    rec.v = heap_caps_malloc(max, MALLOC_CAP_SPIRAM);
    rec.bursts = heap_caps_malloc(REC_MAX_BURSTS * sizeof(burst_t), MALLOC_CAP_SPIRAM);
    rec.ev_t = heap_caps_malloc(REC_MAX_EVENTS * 4, MALLOC_CAP_SPIRAM);
    if (max < 1000 || !rec.t || !rec.v || !rec.bursts || !rec.ev_t) {
        rec_free(); capture_unlock();
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "sem memoria"); return ESP_OK;
    }
    rec.max = max;
    if (adc_pin[0]) {
        int ai = capture_ch_index(adc_pin);
        const char *aerr = adc_bg_open(adc_pin, adc_rate, "11", ai >= 0 && (mask & (1 << ai)));
        if (!aerr) {
            rec.hist = heap_caps_malloc(REC_ADC_HIST * 2, MALLOC_CAP_SPIRAM);
            rec.hist_t = heap_caps_malloc(REC_ADC_HIST * 4, MALLOC_CAP_SPIRAM);
            rec.aev_max = (uint32_t)MIN(60000, (uint64_t)REC_ADC_MAX_EVENTS * (pre + post) * adc_rate / 1000 + 1000);
            rec.aev = heap_caps_malloc(rec.aev_max * 2, MALLOC_CAP_SPIRAM);
            rec.aev_t = heap_caps_malloc(rec.aev_max * 4, MALLOC_CAP_SPIRAM);
            rec.adc_ev = heap_caps_malloc(REC_ADC_MAX_EVENTS * sizeof(adc_ev_t), MALLOC_CAP_SPIRAM);
            if (!rec.hist || !rec.hist_t || !rec.aev || !rec.aev_t || !rec.adc_ev) aerr = "adc: sem memoria";
        }
        if (aerr) {
            adc_bg_close(); rec_free(); capture_unlock();
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, aerr); return ESP_OK;
        }
        rec.adc = true;
        strlcpy(rec.adc_pin, adc_pin, sizeof(rec.adc_pin));
        rec.adc_rate = adc_rate;
        rec.adc_period_cycles = adc_bg_period_cycles();
        rec.pre_ms = pre; rec.post_ms = post;
    }
    capture_apply_pull(pull);
    vTaskDelay(pdMS_TO_TICKS(2));
    rec.start_wall_us = esp_timer_get_time();
    rec.state = 1;
    xTaskCreate(rec_task, "rec", 4096, NULL, 1, &rec.task);
    if (rec.adc) xTaskCreate(rec_adc_task, "rec_adc", 4096, NULL, 3, NULL);
    char buf[200];
    snprintf(buf, sizeof(buf), "{\"ok\":true,\"s\":%d,\"pins\":\"%s\",\"max_edges\":%lu,\"adc\":%s,\"settle_ms\":%d}\n", s, pins,
             (unsigned long)max, rec.adc ? "true" : "false", settle_ms);
    reply_json(req, buf);
    return ESP_OK;
}

// GET /record/status: progresso (ao vivo) e os tempos dos últimos eventos
static esp_err_t record_status_handler(httpd_req_t *req) {
    char buf[700];
    double el = rec.state == 1 ? (esp_timer_get_time() - rec.t0_us) / 1e6 : rec.elapsed_us / 1e6;
    uint32_t n_ev = rec.n_ev;
    int len = snprintf(buf, sizeof(buf),
                       "{\"ok\":true,\"state\":\"%s\",\"s\":%lu,\"elapsed_s\":%.2f,\"edges\":%lu,\"stored\":%lu,\"max_edges\":%lu,"
                       "\"events\":%lu,\"last_events_s\":[",
                       rec.state == 1 ? "recording" : rec.state == 2 ? "done" : "idle", (unsigned long)rec.s, el,
                       (unsigned long)rec.total, (unsigned long)MIN(rec.total, rec.max), (unsigned long)rec.max,
                       (unsigned long)n_ev);
    uint32_t from = n_ev > 20 ? n_ev - 20 : 0;
    for (uint32_t i = from; i < n_ev && len < (int)sizeof(buf) - 30; i++)
        len += snprintf(buf + len, sizeof(buf) - len, "%s%.4f", i > from ? "," : "",
                        (double)((uint64_t)rec.ev_t[i] << REC_SHIFT) / CPU_HZ);
    snprintf(buf + len, sizeof(buf) - len, "]}\n");
    reply_json(req, buf);
    return ESP_OK;
}

// POST /record/stop: encerra agora (os dados continuam disponíveis em /record/data); ?discard=1 apaga
static esp_err_t record_stop_handler(httpd_req_t *req) {
    char q[40] = "", tmp[8] = "";
    httpd_req_get_url_query_str(req, q, sizeof(q));
    bool discard = qp(q, "discard", tmp, sizeof(tmp)) && tmp[0] == '1';
    if (rec.state == 1) {
        rec.stop = true;
        xSemaphoreTake(rec_done_sem, pdMS_TO_TICKS(5000));
        xSemaphoreGive(rec_done_sem);
    }
    if (discard) record_discard_if_done();
    reply_json(req, rec.state == 2 ? "{\"ok\":true,\"state\":\"done\"}\n" : "{\"ok\":true,\"state\":\"idle\"}\n");
    return ESP_OK;
}

// GET /record/data: espera o fim e manda o CSV gpio_edges v1 (ciclos de 240 MHz, 64 bits), com resumo das
// rajadas depois do buffer cheio e, se houver ADC, as janelas analógicas por evento (cycles,raw,mv).
static esp_err_t record_data_handler(httpd_req_t *req) {
    if (rec.state == 0) { httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "nenhuma gravacao"); return ESP_OK; }
    while (rec.state == 1) {
        if (xSemaphoreTake(rec_done_sem, pdMS_TO_TICKS(500)) == pdTRUE) { xSemaphoreGive(rec_done_sem); break; }
        if (client_gone(req)) return ESP_OK;  // os dados ficam para a próxima chamada
    }
    while (rec.task) vTaskDelay(pdMS_TO_TICKS(10));
    httpd_resp_set_type(req, "text/csv");
    char line[300];
    int len = snprintf(line, sizeof(line),
                       "# gpio_edges v1 mode=s2record cpu_hz=%u ms=%lld pull=%s trigger=none edge=any tmode=record pins=%s\n# initial",
                       CPU_HZ, rec.elapsed_us / 1000, rec.pull, rec.pins);
    for (int i = 0; i < N_CH; i++)
        if (rec.mask & (1 << i)) len += snprintf(line + len, sizeof(line) - len, " %s=%d", capture_ch_name(i), (rec.initial >> i) & 1);
    len += snprintf(line + len, sizeof(line) - len, "\ncycles,pin,level\n");
    httpd_resp_send_chunk(req, line, len);
    char *out = heap_caps_malloc(1460, MALLOC_CAP_SPIRAM);  // RAM interna é pouca
    if (!out) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "sem memoria"); return ESP_OK; }
    const int OUTSZ = 1460;
    int olen = 0;
    uint8_t prev = rec.initial;
    for (uint32_t k = 0; k < rec.n; k++) {
        uint8_t ch = (rec.v[k] ^ prev) & rec.mask;
        for (int i = 0; ch && i < N_CH; i++) {
            if (!(ch & (1 << i))) continue;
            if (olen > (int)OUTSZ - 48) {
                if (httpd_resp_send_chunk(req, out, olen) != ESP_OK) { free(out); return ESP_OK; }
                olen = 0;
            }
            olen += snprintf(out + olen, OUTSZ - olen, "%llu,%s,%d\n", (unsigned long long)rec.t[k] << REC_SHIFT,
                             capture_ch_name(i), (rec.v[k] >> i) & 1);
        }
        prev = rec.v[k];
    }
    if (olen) httpd_resp_send_chunk(req, out, olen);
    olen = 0;
    const char *status = rec.total > rec.n ? "buffer_full" : "ok";
    len = snprintf(line, sizeof(line),
                   "# end edges=%lu overflow=%d max_gap_cycles=%lu status=%s loops=%llu max_edges=%lu buf=psram "
                   "total_edges=%lu events=%lu gaps_over_2us=%lu gaps_over_10us=%lu gaps_over_100us=%lu gaps_over_1ms=%lu max_gap_at_ms=%.1f "
                   "bursts_after_full=%lu settle_ticks=%lu err=\n",
                   (unsigned long)rec.n, rec.total > rec.n, (unsigned long)rec.max_gap, status, (unsigned long long)rec.loops,
                   (unsigned long)rec.max, (unsigned long)rec.total, (unsigned long)rec.n_ev, (unsigned long)rec.gaps_over,
                   (unsigned long)rec.gaps_10us, (unsigned long)rec.gaps_100us, (unsigned long)rec.gaps_1ms, rec.max_gap_at / 240000.0,
                   (unsigned long)rec.n_bursts, (unsigned long)rec.settle_ticks);
    httpd_resp_send_chunk(req, line, len);
    for (uint32_t b = 0; b < rec.n_bursts; b++) {
        if (olen > (int)OUTSZ - 80) { httpd_resp_send_chunk(req, out, olen); olen = 0; }
        olen += snprintf(out + olen, OUTSZ - olen, "# burst %llu %llu %lu %d\n", (unsigned long long)rec.bursts[b].t0 << REC_SHIFT,
                         (unsigned long long)rec.bursts[b].t1 << REC_SHIFT, (unsigned long)rec.bursts[b].n, rec.bursts[b].final);
    }
    if (olen) httpd_resp_send_chunk(req, out, olen);
    olen = 0;
    if (rec.adc) {
        len = snprintf(line, sizeof(line),
                       "# adc_samples v1 pin=%s atten_range_mv=2500 rate=%d rate_real=%.1f bits=12 t0=digital mode=events "
                       "pre_ms=%lu post_ms=%lu align=esp_timer\ncycles,raw,mv\n",
                       rec.adc_pin, rec.adc_rate, 240e6 / rec.adc_period_cycles, (unsigned long)rec.pre_ms, (unsigned long)rec.post_ms);
        httpd_resp_send_chunk(req, line, len);
        for (uint32_t e = 0; e < rec.n_adc_ev; e++) {
            for (uint32_t j = rec.adc_ev[e].start; j < rec.adc_ev[e].start + rec.adc_ev[e].n; j++) {
                if (olen > (int)OUTSZ - 40) { httpd_resp_send_chunk(req, out, olen); olen = 0; }
                olen += snprintf(out + olen, OUTSZ - olen, "%llu,%u,%lu\n", (unsigned long long)rec.aev_t[j] << REC_SHIFT,
                                 (unsigned)rec.aev[j], (unsigned long)adc_bg_mv(rec.aev[j]));
            }
        }
        if (olen) httpd_resp_send_chunk(req, out, olen);
        len = snprintf(line, sizeof(line), "# adc_end samples=%lu wanted=%lu windows=%lu lost_events=%lu invalid=%lu period_cycles=%lu\n",
                       (unsigned long)rec.aev_n, (unsigned long)rec.aev_n, (unsigned long)rec.n_adc_ev,
                       (unsigned long)rec.adc_lost_events, (unsigned long)rec.adc_invalid, (unsigned long)rec.adc_period_cycles);
        httpd_resp_send_chunk(req, line, len);
    }
    httpd_resp_send_chunk(req, NULL, 0);
    free(out);
    rec_free();
    rec.state = 0;
    capture_unlock();
    return ESP_OK;
}

void record_register(httpd_handle_t server) {
    const httpd_uri_t uris[] = {
        { .uri = "/record",        .method = HTTP_POST, .handler = record_start_handler },
        { .uri = "/record/status", .method = HTTP_GET,  .handler = record_status_handler },
        { .uri = "/record/stop",   .method = HTTP_POST, .handler = record_stop_handler },
        { .uri = "/record/data",   .method = HTTP_GET,  .handler = record_data_handler },
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) httpd_register_uri_handler(server, &uris[i]);
}
