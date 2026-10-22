idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash esp_wifi esp_http_server esp_event app_update mdns
                             esp_https_ota esp_http_client mbedtls driver esp_timer)
