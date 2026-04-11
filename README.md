# Anker Solix 3 Pro – OLED Display

Live-Statusanzeige für die Anker Solix Solaranlage auf einem ESP32 mit 0,96" OLED.

Läuft vollständig auf dem ESP32 – kein Server, kein Proxy nötig.

## Anzeige

```
Solix 3 Pro        [OK]
────────────────────────
Sol:    450W
Bat:    85% Chr
Hom:    320W
Grd:      0W Bzg
```

| Zeile | Bedeutung                              |
|-------|----------------------------------------|
| Sol   | Aktuelle Solarleistung (W)             |
| Bat   | Batteriestand (%) + Chr/Dch/Stb        |
| Hom   | Hausverbrauch (W)                      |
| Grd   | Netzbezug (+) oder Einspeisung (−) (W) |

## Hardware

| Bauteil | Spezifikation |
|---------|---------------|
| Mikrocontroller | ESP32 (beliebiges Board) |
| Display | 0,96" OLED, 128×64, I2C, SH1106 oder SSD1306 |

### Verdrahtung

| OLED-Pin | ESP32-Pin |
|----------|-----------|
| VCC      | 3,3 V     |
| GND      | GND       |
| SDA      | GPIO 21   |
| SCL      | GPIO 22   |

## Voraussetzungen

- [arduino-cli](https://arduino.github.io/arduino-cli/) oder Arduino IDE 2.x
- ESP32 Board Package: `esp32:esp32` ≥ 3.x
- Bibliotheken: `U8g2`, `ArduinoJson`

### arduino-cli Setup (einmalig)

```bash
arduino-cli config add board_manager.additional_urls \
  https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json

arduino-cli core update-index
arduino-cli core install esp32:esp32
arduino-cli lib install "U8g2" "ArduinoJson"
```

## Installation

```bash
# 1. Konfiguration anlegen
cp oled_anker_direct/config.h.example oled_anker_direct/config.h

# 2. config.h mit Editor öffnen und ausfüllen:
#    - WIFI_SSID / WIFI_PASSWORD
#    - ANKER_EMAIL / ANKER_PASSWORD

# 3. Kompilieren & Flashen
arduino-cli compile --fqbn esp32:esp32:esp32 oled_anker_direct/
arduino-cli upload  --fqbn esp32:esp32:esp32 --port /dev/cu.usbserial-0001 oled_anker_direct/
```

Port unter macOS prüfen: `ls /dev/cu.*`
Port unter Linux: `/dev/ttyUSB0` oder `/dev/ttyACM0`

## Funktionsweise

1. ESP32 verbindet sich mit dem WLAN und synchronisiert die Zeit via NTP
2. **ECDH P-256** – ephemeres Schlüsselpaar wird erzeugt; Shared Secret mit dem Anker-Serverschlüssel berechnet
3. **AES-256-CBC** – Passwort wird mit dem Shared Secret verschlüsselt
4. Login-Request an `https://ankerpower-api-eu.anker.com/passport/login`
5. Alle `REFRESH_SEC` Sekunden werden aktuelle Leistungsdaten von der Anker Cloud abgefragt
6. Token-Ablauf (7 Tage) wird automatisch erkannt und neu eingeloggt

Die Implementierung basiert auf dem Reverse Engineering der Anker API durch
[thomluther/anker-solix-api](https://github.com/thomluther/anker-solix-api).

## Display-Typ anpassen

Die Datei `oled_anker_direct.ino` verwendet standardmäßig den **SH1106**.
Für SSD1306 die folgende Zeile ersetzen:

```cpp
// SH1106 (Standard):
U8G2_SH1106_128X64_NONAME_F_HW_I2C display(U8G2_R2, U8X8_PIN_NONE);

// SSD1306:
U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(U8G2_R2, U8X8_PIN_NONE);
```

`U8G2_R2` = 180° Rotation (Display physisch gedreht montiert).
Ohne Rotation: `U8G2_R0`.
