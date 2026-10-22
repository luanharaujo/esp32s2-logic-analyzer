# Fonte comum: ambiente do ESP-IDF v4.4.5 para o ESP32-S2 (usado pelos outros scripts)
export IDF_PATH="$HOME/repositories/esp/esp-idf-v4.4.5"
IDF_PYTHON="$HOME/.espressif/python_env/idf4.4_py3.12_env/bin/python"
export PATH="$HOME/.espressif/tools/xtensa-esp32s2-elf/esp-2021r2-patch5-8.4.0/xtensa-esp32s2-elf/bin:$HOME/.espressif/python_env/idf4.4_py3.12_env/bin:$PATH"
idf() { "$IDF_PYTHON" "$IDF_PATH/tools/idf.py" "$@"; }
esptool() { "$IDF_PYTHON" -m esptool "$@"; }
export CMAKE_POLICY_VERSION_MINIMUM=3.5  # CMake 4 do Mac recusa os CMakeLists antigos do IDF 4.4
