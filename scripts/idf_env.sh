# Sourced by the other scripts: ESP-IDF v4.4.5 environment for the ESP32-S2.
# Override IDF_PATH or IDF_TOOLS_PATH if the IDF lives somewhere else.
export IDF_PATH="${IDF_PATH:-$HOME/repositories/esp/esp-idf-v4.4.5}"
IDF_TOOLS_PATH="${IDF_TOOLS_PATH:-$HOME/.espressif}"
IDF_PYTHON="$IDF_TOOLS_PATH/python_env/idf4.4_py3.12_env/bin/python"
export PATH="$IDF_TOOLS_PATH/tools/xtensa-esp32s2-elf/esp-2021r2-patch5-8.4.0/xtensa-esp32s2-elf/bin:$IDF_TOOLS_PATH/python_env/idf4.4_py3.12_env/bin:$PATH"
idf() { "$IDF_PYTHON" "$IDF_PATH/tools/idf.py" "$@"; }
esptool() { "$IDF_PYTHON" -m esptool "$@"; }
export CMAKE_POLICY_VERSION_MINIMUM=3.5  # CMake 4 rejects the old CMakeLists files in IDF 4.4.
