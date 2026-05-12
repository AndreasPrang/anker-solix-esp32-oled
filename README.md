# Anker Solix 3 Pro – E-Paper Display

Live status display for the Anker Solix solar system on an ESP32 with a 1.54" 3-colour E-Paper display (Red/Black/White).

Runs entirely on the ESP32 – no server, no proxy required.

## Display

```
Solix 3 Pro          21:07   ← red title + right-aligned time
────────────────────────────── ← red separator
Solar:       0W
Akku:       73%              ← red if < 20 %
Bat-W:      +0W
Haus:      305W
Netz:     0W Bzg
Online
```

| Row    | Description                                          |
|--------|------------------------------------------------------|
| Solar  | Current solar power (W)                              |
| Akku   | Battery state of charge (%) — red when below 20 %   |
| Bat-W  | Battery charge (+) / discharge (−) power (W)         |
| Haus   | Home consumption (W)                                 |
| Netz   | Grid import (Bzg) or export (Ein) (W)                |
| Online | Device connectivity status                           |

The top-right corner shows the time of the last successful data fetch.

> **Note:** 3-colour E-Paper requires a full refresh (~20 s). Partial refresh is not supported by this panel type.

## Hardware

| Component | Specification |
|-----------|---------------|
| Microcontroller | ESP32 WROOM-32 (or any ESP32 board) |
| Display | 1.54" E-Paper, 200×200, 3-colour (Red/Black/White), SPI |
| Display driver | SSD1682 / GDEW0154Z90 (Seengreat Rev 1.2) |

### Wiring

| E-Paper pin | ESP32 pin | Notes |
|-------------|-----------|-------|
| VCC         | 3V3       |       |
| GND         | GND       |       |
| DIN (MOSI)  | G23       | Hardware SPI |
| CLK         | G18       | Hardware SPI |
| CS          | G5        | `EPD_CS` in config.h |
| D/C         | G17       | `EPD_DC` in config.h |
| RST         | G16       | `EPD_RST` in config.h |
| BUSY        | G4        | `EPD_BUSY` in config.h (wired but unused — delay-based timing) |

## Requirements

- [arduino-cli](https://arduino.github.io/arduino-cli/) or Arduino IDE 2.x
- ESP32 board package: `esp32:esp32` ≥ 3.x
- Libraries: `GxEPD2`, `Adafruit GFX Library`, `ArduinoJson`

### arduino-cli setup (once)

```bash
arduino-cli config add board_manager.additional_urls \
  https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json

arduino-cli core update-index
arduino-cli core install esp32:esp32
arduino-cli lib install "GxEPD2" "Adafruit GFX Library" "ArduinoJson"
```

## Installation

```bash
# 1. Create config file
cp oled_anker_direct/config.h.example oled_anker_direct/config.h

# 2. Open config.h and fill in your values:
#    - WIFI_SSID / WIFI_PASSWORD
#    - ANKER_EMAIL / ANKER_PASSWORD
#    - LANGUAGE  (de or en)
#    - EPD_CS / EPD_DC / EPD_RST / EPD_BUSY  (SPI pins)

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

## Display variants

The `SH1106_128x64` branch contains the original version using a 0.96" SH1106 I2C OLED.
The `main` branch targets the 1.54" 3-colour E-Paper display described above.
