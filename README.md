# esp32s2-logic-analyzer

A logic analyzer you reach over Wi-Fi, built on the Wi-Fi Devboard for Flipper Zero (ESP32-S2) running on its own, powered by a USB charger. It captures edges on 8 channels at about 0.1 us resolution, samples one analog channel at up to 83333 samples/s, and records for up to 280 s. A Python client turns each capture into a summary (bounce duration, pulse widths, frequency, duty) and a plot, from the command line or as an MCP server.

I built it to measure button bounce on an STM32 NUCLEO board without leaving a USB port taken: after the first flash, every firmware update goes over the network.

## Hardware

The channels are the devboard pins you can clip onto without soldering:

| Channel | GPIO | Header pin | Notes |
|---|---|---|---|
| IO10 | 10 | 5 | also ADC1_CH9 |
| IO11 | 11 | 2 | |
| IO12 | 12 | 4 | |
| IO13 | 13 | 3 | |
| IO1 | 1 | 10 | also ADC1_CH0 |
| IO2 | 2 | 12 | also ADC1_CH1 |
| IO18 | 18 | 15 | check for an external pull-up first |
| IO17 | 17 | 16 | check for an external pull-up first |

GND is on header pins 8, 11 and 18. Keep GND common with the target.

The ESP32-S2 GPIOs are 3.3 V only. A 5 V target needs a divider or a 74LVC buffer.

Leave header pins 6 and 7 alone: they drive the auto-reset and boot circuit. On the analog side, ADC1 with 11 dB attenuation reads 0 to about 2.5 V, so a 3.3 V signal flattens at the top. That does not harm the pin.

## How the capture works

The 8 GPIOs form a dedicated GPIO bundle, so one `get_gpio_in` instruction reads all of them in a single cycle. A loop in IRAM, with interrupts masked, reads the pins and the 240 MHz cycle counter and stores only the changes. One pass takes about 22 cycles, about 0.1 us.

The trade-off is Wi-Fi: while the loop runs, nothing else does, so `/capture` windows are capped at 2000 ms. The polling trigger waits in 100 ms slices and gives Wi-Fi a 1 ms break between them. An edge that lands in a break is still caught at the start of the next slice and reported as `status=trigger_in_gap`. If you need Wi-Fi alive while waiting, `tmode=isr` uses a GPIO interrupt instead. That costs 1 to 2 us of latency.

`/record` takes the other side of that trade-off. The same polling loop runs in a low-priority task with interrupts enabled, so Wi-Fi and HTTP stay up for up to 280 s and 250k edges in PSRAM. Over 10 s idle I measured about 200 gaps over 100 us, about 5 over 1 ms and a maximum near 5 ms. The CSV reports these gaps, so you know when a short pulse may have been missed.

The self-test drives a known bounce burst out of the RMT and a 10 kHz square wave out of the LEDC, then captures them on the same pins. On the board, the bounce widths came back within 0.09 us and the 10 kHz, 30% wave measured 9990 to 10010 Hz and 29.6 to 29.8%.

## Build and flash

The firmware uses ESP-IDF v4.4.5. `scripts/idf_env.sh` reads `IDF_PATH` and `IDF_TOOLS_PATH` from the environment.

1. Copy `firmware/main/wifi_secrets.example.h` to `firmware/main/wifi_secrets.h` and fill in the SSID, password and a 32-hex-character token. Save the same token in `~/.config/s2la/token`.
2. First flash over USB: hold BOOT while plugging in, then run `scripts/usb_backup.sh` (reads the whole flash into `backup/`) and `scripts/usb_flash.sh`. Unplug and plug back in without pressing anything.
3. From then on: `./ota_update.sh` builds the firmware, pushes it by HTTP POST and checks the version after the reboot. A new image that cannot bring the network up within 3 min rolls back to the previous one on its own.

The board announces itself as `logic-s2.local` over mDNS. If two access points share your SSID and one of them is unreachable, list its BSSID prefix in `WIFI_AVOID_BSSID_PREFIXES`. The firmware then tries it last and switches away when the preferred one shows up.

## Client

```
uv run agent/analyzer.py status
uv run agent/analyzer.py capture --ms 100 --trigger IO10 --edge fall --pins IO10
uv run agent/analyzer.py capture --ms 20 --trigger IO10 --edge fall --adc-pin IO1   # digital + analog, one time base
uv run agent/analyzer.py record --s 120 --pins IO10 --adc-pin IO1 --show
uv run agent/analyzer.py live --pin IO1
uv run agent/analyzer.py adc-log --adc-pin IO1 --out log.csv   # until Ctrl-C, epoch_ms,mv
uv run agent/analyzer.py adc-plot log.csv
uv run agent/analyzer.py combo-log --pins IO10 --adc-pin IO1 --out combo.csv   # digital + analog, same clock, until Ctrl-C
uv run agent/analyzer.py combo-plot combo.csv --show
uv run agent/analyzer.py selftest
uv run agent/analyzer.py mcp
```

Every capture is saved as CSV in `captures/` (`gpio_edges v1`, 240 MHz cycles, the same format as a Flipper FAP that logs GPIO edges). `presses` applies the same rule as an STM32 stopwatch firmware: a press counts after 20 ms stable at 0, timed at the last falling edge. It can then match laps against a reference list and fit the clock ratio between the two boards.

`uv run tests/test_offline.py` runs the client against a fake ESP, so no hardware is needed.

## HTTP API

`GET /` on the board lists every route. The main ones:

- `GET /capture?ms=&trigger=&edge=&timeout_ms=&pull=&pins=&tmode=[&adc_pin=&adc_rate=&adc_atten=]`
- `GET /adc?pin=&ms=&rate=&atten=[&trig_mv=&edge=&pre=]`
- `POST /record?s=&pins=[&adc_pin=&adc_rate=]`, `GET /record/status`, `GET /record/data`, `POST /record/stop`
- `GET /status`, `GET /log[?prev=1]`, `GET /levels`, `GET /channels`, `GET /scan`
- `POST /ota` (body = .bin, `X-Token`, optional `X-SHA256`), `POST /gen`, `POST /reboot`

Routes that change the board need the `X-Token` header.
