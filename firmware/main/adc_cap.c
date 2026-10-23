// Captura analógica (lenta) num canal do ADC1, pelo modo contínuo (DMA) do ESP32-S2.
//
// Pinos: só os do ADC1 que estão no header sem solda: IO1 (ADC1_CH0, pino 10), IO2 (ADC1_CH1, pino 12) e
// IO10 (ADC1_CH9, pino 5). Os outros canais sem solda (IO11/12/13/17/18) são do ADC2, que o Wi-Fi usa:
// no S2 o árbitro dá prioridade ao Wi-Fi e as leituras falham ou vêm inválidas com o Wi-Fi ligado.
// Velocidade: o modo contínuo da IDF 4.4 aceita 611 a 83333 amostras/s no S2 (SOC_ADC_SAMPLE_FREQ_THRES_*),
// 12 bits por amostra (formato TYPE1, unidade única). O DMA (do SPI3) enche um anel de bytes; a tarefa
// do HTTP copia para a PSRAM, sem mascarar interrupções: Wi-Fi e watchdog seguem normais.
// Pino: o driver desliga a entrada digital e os pulls do pad (gpio_config MODE_DISABLE). Nada de pull é
// ligado. No fim, o registrador IO_MUX do pino volta exatamente ao que era (entrada, pulls, função), e o
// bundle de GPIO dedicado da captura digital continua ligado (a matriz de entrada não é tocada).
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/param.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "driver/adc.h"
#include "esp_adc_cal.h"
#include "soc/gpio_periph.h"
#include "soc/io_mux_reg.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hal/cpu_hal.h"
#include "capture.h"

static const char *TAG = "ADC";

#define ADC_MAX_SAMPLES 200000
#define ADC_MAX_MS 10000
#define ADC_CHUNK_BYTES 512   // bytes por interrupção do DMA (256 amostras, ~3 ms a 83 kHz)
#define ADC_RING_BYTES 8192   // folga do anel (~50 ms a 83 kHz)
#define TRIG_MAX_TIMEOUT_MS 300000

typedef struct { const char *name; int gpio; int ch; int header_pin; } adc_pin_t;
static const adc_pin_t adc_pins[] = {
    { "IO10", 10, ADC1_CHANNEL_9, 5 },
    { "IO1", 1, ADC1_CHANNEL_0, 10 },
    { "IO2", 2, ADC1_CHANNEL_1, 12 },
};
// Canais sem solda que são do ADC2 (só para a mensagem de erro)
static const char *adc2_names[] = { "IO11", "IO12", "IO13", "IO17", "IO18" };

// Faixa recomendada pela IDF 4.4 para o S2 (mV) por atenuação; usada como fundo de escala nominal
// quando o chip não tem calibração no eFuse
typedef struct { const char *name; adc_atten_t atten; int range_mv; } atten_t;
static const atten_t attens[] = {
    { "0", ADC_ATTEN_DB_0, 750 }, { "2.5", ADC_ATTEN_DB_2_5, 1050 }, { "6", ADC_ATTEN_DB_6, 1300 }, { "11", ADC_ATTEN_DB_11, 2500 },
};

// Taxa real no S2: o controlador digital roda a 5 MHz (APB/16) e dispara a cada 2*interval ciclos, com
// interval = 2500000 / rate (inteiro). Uma amostra = 96 * interval ciclos da CPU de 240 MHz.
static inline uint32_t adc_interval(int rate) { return 2500000u / (uint32_t)rate; }
static inline double adc_real_rate(int rate) { return 2500000.0 / adc_interval(rate); }

static bool qparam(const char *q, const char *key, char *out, size_t n) {
    return q && httpd_query_key_value(q, key, out, n) == ESP_OK;
}

static const adc_pin_t *find_pin(const char *name) {
    for (size_t i = 0; i < sizeof(adc_pins) / sizeof(adc_pins[0]); i++) {
        if (strcasecmp(name, adc_pins[i].name) == 0) return &adc_pins[i];
        if (name[0] >= '0' && name[0] <= '9' && atoi(name) == adc_pins[i].gpio) return &adc_pins[i];
    }
    return NULL;
}

static bool is_adc2(const char *name) {
    for (size_t i = 0; i < sizeof(adc2_names) / sizeof(adc2_names[0]); i++) {
        if (strcasecmp(name, adc2_names[i]) == 0) return true;
        if (name[0] >= '0' && name[0] <= '9' && atoi(name) == atoi(adc2_names[i] + 2)) return true;
    }
    return false;
}

// Conversão para mV: calibração de 2 pontos do eFuse (13 bits) se existir; senão, linear nominal.
static esp_adc_cal_characteristics_t cal_chars;
static bool cal_ok = false;
static int cal_range_mv = 2500;
static inline uint32_t raw_to_mv(uint32_t raw12) {
    if (cal_ok) return esp_adc_cal_raw_to_voltage(raw12 << 1, &cal_chars);
    return raw12 * (uint32_t)cal_range_mv / 4095u;
}

// GET /adc?pin=IO10&ms=100&rate=83333&atten=11[&trig_mv=1650&edge=fall|rise&timeout_ms=10000&pre=100]
// Resposta: CSV "adc_samples v1": us,raw,mv (t=0 na 1a amostra, ou na amostra do trigger, com as do
// pré-trigger negativas). raw = 12 bits (0..4095). No fim: amostras, taxa medida, falhas, status.
static esp_err_t adc_handler(httpd_req_t *req) {
    char q[200] = "", tmp[32], pin[12] = "IO10", edge[8] = "fall", att[8] = "11";
    httpd_req_get_url_query_str(req, q, sizeof(q));
    int ms = 100, rate = SOC_ADC_SAMPLE_FREQ_THRES_HIGH, timeout_ms = 10000, trig_mv = -1, pre = 100;
    qparam(q, "pin", pin, sizeof(pin));
    qparam(q, "edge", edge, sizeof(edge));
    qparam(q, "atten", att, sizeof(att));
    if (qparam(q, "ms", tmp, sizeof(tmp))) ms = atoi(tmp);
    if (qparam(q, "rate", tmp, sizeof(tmp))) rate = atoi(tmp);
    if (qparam(q, "timeout_ms", tmp, sizeof(tmp))) timeout_ms = atoi(tmp);
    if (qparam(q, "trig_mv", tmp, sizeof(tmp)) && tmp[0]) trig_mv = atoi(tmp);
    if (qparam(q, "pre", tmp, sizeof(tmp))) pre = atoi(tmp);

    const adc_pin_t *p = find_pin(pin);
    if (!p) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            is_adc2(pin) ? "pino do ADC2 (conflita com o Wi-Fi); use IO10, IO1 ou IO2 (ADC1)"
                                         : "pin: use IO10, IO1 ou IO2 (ADC1)");
        return ESP_OK;
    }
    const atten_t *a = NULL;
    for (size_t i = 0; i < sizeof(attens) / sizeof(attens[0]); i++)
        if (strcmp(att, attens[i].name) == 0) a = &attens[i];
    if (!a) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "atten: 0, 2.5, 6 ou 11"); return ESP_OK; }
    if (rate < SOC_ADC_SAMPLE_FREQ_THRES_LOW || rate > SOC_ADC_SAMPLE_FREQ_THRES_HIGH) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "rate fora de 611..83333"); return ESP_OK;
    }
    if (ms < 1 || ms > ADC_MAX_MS) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ms fora de 1..10000"); return ESP_OK; }
    uint32_t n_want = (uint32_t)((int64_t)ms * rate / 1000);
    if (n_want < 1) n_want = 1;
    if (n_want > ADC_MAX_SAMPLES) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ms*rate acima de 200000 amostras"); return ESP_OK; }
    pre = MAX(0, MIN(pre, ADC_CHUNK_BYTES / 2));
    timeout_ms = MAX(1, MIN(timeout_ms, TRIG_MAX_TIMEOUT_MS));
    bool rise = strcmp(edge, "rise") == 0;

    if (capture_is_busy()) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "ocupado (OTA)"); return ESP_OK; }
    if (!capture_lock(0)) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "outra captura em andamento"); return ESP_OK; }

    uint32_t n_buf = n_want + (trig_mv >= 0 ? (uint32_t)pre : 0);
    uint16_t *buf = heap_caps_malloc(n_buf * 2, MALLOC_CAP_SPIRAM);
    if (!buf) buf = heap_caps_malloc(n_buf * 2, MALLOC_CAP_8BIT);
    uint8_t *chunk = heap_caps_malloc(ADC_CHUNK_BYTES, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!buf || !chunk) {
        free(buf); free(chunk); capture_unlock();
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "sem memoria"); return ESP_OK;
    }

    cal_ok = esp_adc_cal_check_efuse(ESP_ADC_CAL_VAL_EFUSE_TP) == ESP_OK;
    if (cal_ok) esp_adc_cal_characterize(ADC_UNIT_1, a->atten, ADC_WIDTH_BIT_13, 0, &cal_chars);
    cal_range_mv = a->range_mv;

    // Guarda o pad do pino inteiro (entrada, pulls, função) para devolver no fim
    uint32_t iomux_saved = REG_READ(GPIO_PIN_MUX_REG[p->gpio]);

    const char *status = "ok";
    uint32_t n = 0, invalid = 0, overflow = 0, chunks = 0;
    int32_t trig_idx = -1;
    int64_t t_first = 0, t_last = 0, t_arm = esp_timer_get_time();
    uint32_t n_counted = 0;  // amostras vistas desde o 1o bloco (para a taxa medida)

    adc_digi_init_config_t ic = { .max_store_buf_size = ADC_RING_BYTES, .conv_num_each_intr = ADC_CHUNK_BYTES,
                                  .adc1_chan_mask = BIT(p->ch), .adc2_chan_mask = 0 };
    esp_err_t err = adc_digi_initialize(&ic);
    if (err == ESP_OK) {
        adc_digi_pattern_config_t pat = { .atten = a->atten, .channel = p->ch, .unit = 0, .bit_width = SOC_ADC_DIGI_MAX_BITWIDTH };
        adc_digi_configuration_t dc = { .conv_limit_en = 0, .conv_limit_num = 250, .pattern_num = 1, .adc_pattern = &pat,
                                        .sample_freq_hz = (uint32_t)rate, .conv_mode = ADC_CONV_SINGLE_UNIT_1,
                                        .format = ADC_DIGI_OUTPUT_FORMAT_TYPE1 };
        err = adc_digi_controller_configure(&dc);
    }
    if (err == ESP_OK) err = adc_digi_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "adc_digi: %s", esp_err_to_name(err));
        status = "adc_error";
    } else {
        int64_t deadline = t_arm + (int64_t)timeout_ms * 1000 + (int64_t)ms * 1000 + 500000;
        int prev_mv = -1;
        bool started = trig_mv < 0;
        while (n < n_buf) {
            uint32_t got = 0;
            esp_err_t r = adc_digi_read_bytes(chunk, ADC_CHUNK_BYTES, &got, 100);
            int64_t now = esp_timer_get_time();
            if (r == ESP_ERR_INVALID_STATE) overflow = 1;
            if (r == ESP_ERR_TIMEOUT || got == 0) {
                if (now > deadline) { status = started ? "stalled" : "timeout"; break; }
                continue;
            }
            if (chunks++ == 0) t_first = now;
            else n_counted += got / 2;
            t_last = now;
            const adc_digi_output_data_t *d = (const adc_digi_output_data_t *)chunk;
            uint32_t m = got / 2;
            if (!started) {
                // procura o cruzamento do limiar neste bloco; guarda até `pre` amostras antes dele
                for (uint32_t i = 0; i < m; i++) {
                    if (d[i].type1.channel != p->ch) continue;
                    int mv = (int)raw_to_mv(d[i].type1.data);
                    if (prev_mv >= 0 && (rise ? (prev_mv < trig_mv && mv >= trig_mv) : (prev_mv > trig_mv && mv <= trig_mv))) {
                        uint32_t k0 = i > (uint32_t)pre ? i - pre : 0;
                        for (uint32_t k = k0; k < m && n < n_buf; k++) {
                            if (d[k].type1.channel != p->ch) { invalid++; continue; }
                            if (k == i) trig_idx = (int32_t)n;
                            buf[n++] = d[k].type1.data;
                        }
                        started = true;
                        break;
                    }
                    prev_mv = mv;
                }
                if (!started && now > t_arm + (int64_t)timeout_ms * 1000) { status = "timeout"; break; }
                if (!started && (chunks & 63) == 0 && client_gone(req)) { status = "client_gone"; break; }
                continue;
            }
            for (uint32_t i = 0; i < m && n < n_buf; i++) {
                if (d[i].type1.channel != p->ch) { invalid++; continue; }
                buf[n++] = d[i].type1.data;
            }
            if (trig_idx >= 0 && n >= (uint32_t)trig_idx + n_want) break;
            if (trig_idx < 0 && n >= n_want) break;
        }
        adc_digi_stop();
    }
    if (overflow && strcmp(status, "ok") == 0) status = "overflow";
    adc_digi_deinitialize();
    REG_WRITE(GPIO_PIN_MUX_REG[p->gpio], iomux_saved);
    int64_t waited_us = esp_timer_get_time() - t_arm;
    double sps = (t_last > t_first && n_counted) ? n_counted * 1e6 / (double)(t_last - t_first) : 0;

    // CSV
    httpd_resp_set_type(req, "text/csv");
    char line[300];
    int len = snprintf(line, sizeof(line),
                       "# adc_samples v1 pin=%s gpio=%d header_pin=%d unit=1 ch=%d atten=%s range_mv=%d rate=%d rate_real=%.1f bits=12 "
                       "cal=%s trig_mv=%d edge=%s pre=%d\nus,raw,mv\n",
                       p->name, p->gpio, p->header_pin, p->ch, a->name, a->range_mv, rate, adc_real_rate(rate), cal_ok ? "efuse_tp" : "nominal",
                       trig_mv, trig_mv >= 0 ? edge : "none", trig_mv >= 0 ? pre : 0);
    httpd_resp_send_chunk(req, line, len);
    static char out[1460];
    int olen = 0;
    int32_t t0 = trig_idx >= 0 ? trig_idx : 0;
    for (uint32_t k = 0; k < n; k++) {
        if (olen > (int)sizeof(out) - 32) { httpd_resp_send_chunk(req, out, olen); olen = 0; }
        double us = ((int32_t)k - t0) * 1e6 / adc_real_rate(rate);
        olen += snprintf(out + olen, sizeof(out) - olen, "%.1f,%u,%lu\n", us, (unsigned)buf[k], (unsigned long)raw_to_mv(buf[k]));
    }
    if (olen) httpd_resp_send_chunk(req, out, olen);
    len = snprintf(line, sizeof(line),
                   "# end samples=%lu sps_measured=%.0f invalid=%lu overflow=%lu trig_index=%ld status=%s wait_ms=%lld err=%s\n",
                   (unsigned long)n, sps, (unsigned long)invalid, (unsigned long)overflow, (long)trig_idx, status,
                   waited_us / 1000, err == ESP_OK ? "" : esp_err_to_name(err));
    httpd_resp_send_chunk(req, line, len);
    httpd_resp_send_chunk(req, NULL, 0);
    ESP_LOGI(TAG, "adc %s %s: %lu amostras, %.0f amostras/s medidas, %lu invalidas", p->name, status, (unsigned long)n, sps,
             (unsigned long)invalid);
    free(buf);
    free(chunk);
    capture_unlock();
    return ESP_OK;
}

// ---------------------------------------------------------------------------------------------------
// ADC em segundo plano para a captura combinada (/capture com adc_pin=): o DMA enche uma cadeia de 5
// descritores em RAM interna sem precisar da CPU, enquanto o laço digital roda com as interrupções
// mascaradas. A cadeia não é renovada durante a janela (a ISR do DMA está mascarada), então a parte
// analógica cobre no máximo adc_bg_chain_samples() amostras a partir do último adc_bg_restart().
static const adc_pin_t *bg_pin = NULL;
static uint32_t bg_iomux = 0, bg_chunk = 0;
static int bg_rate = 0;
static bool bg_started = false, bg_keep_digital = false, bg_alive = false;
static adc_digi_init_config_t bg_ic;
static adc_digi_pattern_config_t bg_pat;
static adc_digi_configuration_t bg_dc;

const char *adc_bg_open(const char *pin, int rate, const char *atten, bool keep_digital) {
    const adc_pin_t *p = find_pin(pin);
    if (!p) return is_adc2(pin) ? "adc_pin do ADC2 (conflita com o Wi-Fi); use IO1, IO2 ou IO10" : "adc_pin: use IO1, IO2 ou IO10";
    const atten_t *a = NULL;
    for (size_t i = 0; i < sizeof(attens) / sizeof(attens[0]); i++)
        if (strcmp(atten, attens[i].name) == 0) a = &attens[i];
    if (!a) return "adc_atten: 0, 2.5, 6 ou 11";
    if (rate < SOC_ADC_SAMPLE_FREQ_THRES_LOW || rate > SOC_ADC_SAMPLE_FREQ_THRES_HIGH) return "adc_rate fora de 611..83333";
    // Cadeia = 5 blocos em RAM interna (DMA). Deixa ~12 KB de folga para o Wi-Fi; bloco de 256 a 4092 bytes.
    size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA);
    int32_t chunk = largest > 12 * 1024 ? (int32_t)(largest - 12 * 1024) / 5 : 0;
    chunk = MIN(chunk, 4092) & ~3;
    if (chunk < 256) return "adc: pouca RAM interna para o DMA";
    cal_ok = esp_adc_cal_check_efuse(ESP_ADC_CAL_VAL_EFUSE_TP) == ESP_OK;
    if (cal_ok) esp_adc_cal_characterize(ADC_UNIT_1, a->atten, ADC_WIDTH_BIT_13, 0, &cal_chars);
    cal_range_mv = a->range_mv;
    bg_iomux = REG_READ(GPIO_PIN_MUX_REG[p->gpio]);
    // anel > 16 KB para ir para a PSRAM; cabe a cadeia inteira de uma vez (a ISR despeja tudo ao desmascarar)
    bg_ic = (adc_digi_init_config_t){ .max_store_buf_size = MAX(17 * 1024, 6 * (uint32_t)chunk), .conv_num_each_intr = (uint32_t)chunk,
                                      .adc1_chan_mask = BIT(p->ch), .adc2_chan_mask = 0 };
    bg_pat = (adc_digi_pattern_config_t){ .atten = a->atten, .channel = p->ch, .unit = 0, .bit_width = SOC_ADC_DIGI_MAX_BITWIDTH };
    bg_dc = (adc_digi_configuration_t){ .conv_limit_en = 0, .conv_limit_num = 250, .pattern_num = 1, .adc_pattern = &bg_pat,
                                        .sample_freq_hz = (uint32_t)rate, .conv_mode = ADC_CONV_SINGLE_UNIT_1,
                                        .format = ADC_DIGI_OUTPUT_FORMAT_TYPE1 };
    esp_err_t err = adc_digi_initialize(&bg_ic);
    if (err == ESP_OK) err = adc_digi_controller_configure(&bg_dc);
    if (err != ESP_OK) {
        adc_digi_deinitialize();
        REG_WRITE(GPIO_PIN_MUX_REG[p->gpio], bg_iomux);
        ESP_LOGE(TAG, "adc_bg: %s", esp_err_to_name(err));
        return "adc: falha ao iniciar o DMA";
    }
    // keep_digital: devolve a entrada digital (e os pulls do /capture) ao pad, para o mesmo pino servir
    // também de canal digital. Experimental: o ADC lê o pad com o buffer digital ligado.
    if (keep_digital) REG_WRITE(GPIO_PIN_MUX_REG[p->gpio], bg_iomux);
    bg_keep_digital = keep_digital;
    bg_alive = true;
    bg_pin = p;
    bg_chunk = (uint32_t)chunk;
    bg_rate = rate;
    return NULL;
}

uint32_t adc_bg_chain_samples(void) { return bg_pin ? bg_chunk * 5 / 2 : 0; }
uint32_t adc_bg_period_cycles(void) { return bg_pin ? 96u * adc_interval(bg_rate) : 0; }

// Recomeça uma cadeia nova, descartando o que havia. *t0 = ciclo da CPU logo depois de ligar o disparo
// (a 1a amostra sai ~1 período depois). Não usa adc_digi_stop + adc_digi_start + leitura para esvaziar:
// depois de um stop no meio de um bloco, o anel do driver da IDF 4.4 fica com pedaços de tamanho que não
// é múltiplo de 4 e adc_digi_read_bytes dá assert ((size % 4) == 0) -> panic (visto no 0.3.1/0.3.2).
// Em vez disso, desmonta e remonta o driver (o anel é apagado sem ser lido), ~1 ms.
void adc_bg_restart(uint32_t *t0) {
    if (!bg_pin) return;
    if (bg_started) {
        diag_mark("adc:reinit");
        adc_digi_stop();
        adc_digi_deinitialize();
        bg_started = false;
        bg_alive = false;
        if (adc_digi_initialize(&bg_ic) != ESP_OK || adc_digi_controller_configure(&bg_dc) != ESP_OK) {
            adc_digi_deinitialize();
            ESP_LOGE(TAG, "adc_bg: falha ao remontar");
            *t0 = cpu_hal_get_cycle_count();
            return;
        }
        if (bg_keep_digital) REG_WRITE(GPIO_PIN_MUX_REG[bg_pin->gpio], bg_iomux);
        bg_alive = true;
    }
    diag_mark("adc:start");
    bg_started = bg_alive && adc_digi_start() == ESP_OK;
    diag_mark("adc:running");
    *t0 = cpu_hal_get_cycle_count();
}

// Lê até n amostras da cadeia (espera no máx. timeout_ms). Devolve quantas; *invalid = descartadas.
uint32_t adc_bg_collect(uint16_t *buf, uint32_t n, uint32_t timeout_ms, uint32_t *invalid) {
    static uint8_t chunk[512];
    uint32_t k = 0;
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (bg_pin && bg_alive && bg_started && k < n && esp_timer_get_time() < deadline) {
        uint32_t got = 0;
        esp_err_t r = adc_digi_read_bytes(chunk, sizeof(chunk), &got, 20);
        if (r == ESP_ERR_TIMEOUT || !got) continue;
        const adc_digi_output_data_t *d = (const adc_digi_output_data_t *)chunk;
        for (uint32_t i = 0; i < got / 2 && k < n; i++) {
            if (d[i].type1.channel != bg_pin->ch) { (*invalid)++; continue; }
            buf[k++] = d[i].type1.data;
        }
    }
    return k;
}

uint32_t adc_bg_mv(uint32_t raw) { return raw_to_mv(raw); }

// Cabeçalho da seção analógica do CSV combinado
int adc_bg_header(char *out, size_t n) {
    if (!bg_pin) return 0;
    return snprintf(out, n, "# adc_samples v1 pin=%s gpio=%d header_pin=%d unit=1 ch=%d atten_range_mv=%d rate=%d rate_real=%.1f "
                            "bits=12 cal=%s t0=digital chain=%lu\n",
                    bg_pin->name, bg_pin->gpio, bg_pin->header_pin, bg_pin->ch, cal_range_mv, bg_rate, adc_real_rate(bg_rate),
                    cal_ok ? "efuse_tp" : "nominal", (unsigned long)adc_bg_chain_samples());
}

void adc_bg_close(void) {
    if (!bg_pin) return;
    if (bg_started) adc_digi_stop();
    bg_started = false;
    if (bg_alive) adc_digi_deinitialize();
    bg_alive = false;
    REG_WRITE(GPIO_PIN_MUX_REG[bg_pin->gpio], bg_iomux);
    bg_pin = NULL;
}

void adc_register(httpd_handle_t server) {
    const httpd_uri_t u = { .uri = "/adc", .method = HTTP_GET, .handler = adc_handler };
    httpd_register_uri_handler(server, &u);
}
