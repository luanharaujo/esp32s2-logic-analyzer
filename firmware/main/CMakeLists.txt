idf_component_register(SRCS "main.c" "capture.c" "adc_cap.c" "record.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash esp_wifi esp_http_server esp_event app_update mdns
                             esp_https_ota esp_http_client mbedtls driver esp_timer esp_adc_cal)
# Keeps the panic/abort reason in RTC memory (see main.c).
target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=esp_panic_handler" "-Wl,--wrap=esp_system_abort")
