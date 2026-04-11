# Anker Solix 3 Pro – OLED Display

Live status display for the Anker Solix solar system on an ESP32 with a 0.96" OLED.

Runs entirely on the ESP32 – no server, no proxy required.

## Display

```
Solix 3 Pro        14:35
────────────────────────
Solar:    450W
Akku:      85%
Haus:     320W
Netz:       0W Bzg
```

| Row   | Description                              |
|-------|------------------------------------------|
| Solar | Current solar power (W)                  |
| Akku  | Battery state of charge (%)              |
| Haus  | Home consumption (W)                     |
| Netz  | Grid import (+) or export (−) (W)        |

The top-right corner shows the time of the last successful data fetch.

## Hardware

| Component | Specification |
|-----------|---------------|
| Microcontroller | ESP32 (any board) |
| Display | 0.96" OLED, 128×64, I2C, SH1106 or SSD1306 |

### Wiring

| OLED pin | ESP32 pin |
|----------|-----------|
| VCC      | 3.3 V     |
| GND      | GND       |
| SDA      | GPIO 21   |
| SCL      | GPIO 22   |

## Requirements

- [arduino-cli](https://arduino.github.io/arduino-cli/) or Arduino IDE 2.x
- ESP32 board package: `esp32:esp32` ≥ 3.x
- Libraries: `U8g2`, `ArduinoJson`

### arduino-cli setup (once)

```bash
arduino-cli config add board_manager.additional_urls \
  https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json

arduino-cli core update-index
arduino-cli core install esp32:esp32
arduino-cli lib install "U8g2" "ArduinoJson"
```

## Installation

```bash
# 1. Create config file
cp oled_anker_direct/config.h.example oled_anker_direct/config.h

# 2. Open config.h and fill in your values:
#    - WIFI_SSID / WIFI_PASSWORD
#    - ANKER_EMAIL / ANKER_PASSWORD
#    - LANGUAGE  (de or en)

# 3. Compile & flash
arduino-cli compile --fqbn esp32:esp32:esp32 oled_anker_direct/
arduino-cli upload  --fqbn esp32:esp32:esp32 --port /dev/cu.usbserial-0001 oled_anker_direct/
```

Find the port on macOS: `ls /dev/cu.*`
Find the port on Linux: `/dev/ttyUSB0` or `/dev/ttyACM0`

## How it works

1. The ESP32 connects to WiFi and syncs time via NTP (timezone is set via POSIX TZ string, DST handled automatically)
2. **ECDH P-256** – an ephemeral key pair is generated; the shared secret is computed against the Anker server public key
3. **AES-256-CBC** – the password is encrypted using the shared secret
4. Login request to `https://ankerpower-api-eu.anker.com/passport/login`
5. Every `REFRESH_SEC` seconds, current power data is fetched from the Anker Cloud
6. Token expiry (7 days) is detected automatically and triggers a re-login

This implementation is based on the reverse engineering of the Anker API by
[thomluther/anker-solix-api](https://github.com/thomluther/anker-solix-api).

## Changing the display type

`oled_anker_direct.ino` uses the **SH1106** by default.
For SSD1306, replace the following line:

```cpp
// SH1106 (default):
U8G2_SH1106_128X64_NONAME_F_HW_I2C display(U8G2_R2, U8X8_PIN_NONE);

// SSD1306:
U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(U8G2_R2, U8X8_PIN_NONE);
```

`U8G2_R2` = 180° rotation (display mounted upside down).
No rotation: `U8G2_R0`.
