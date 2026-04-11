/**
 * Anker Solix 3 Pro – direktes OLED Status Display
 * ESP32 + 0.96" SH1106 128×64 I2C
 *
 * Authentifizierung direkt gegen Anker Cloud:
 *   ECDH P-256  → Shared Secret
 *   AES-256-CBC → Passwort-Verschlüsselung
 *   MD5         → gtoken
 *
 * Keine Middleware nötig – läuft komplett auf dem ESP32.
 */

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <U8g2lib.h>
#include <Wire.h>
#include <time.h>

// mbedTLS (in ESP32 Arduino Framework enthalten)
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/aes.h"
#include "mbedtls/md5.h"
#include "mbedtls/base64.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "config.h"

// ── Sprach-Makros ──────────────────────────────────────────
// In config.h: #define LANGUAGE de   (oder en)
// Wählt zur Kompilierzeit die richtige Sprache.
// Zwei Indirektions-Ebenen nötig, damit LANGUAGE vor ## expandiert wird.
#define _LANG_de(de, en)    de
#define _LANG_en(de, en)    en
#define _LANG_PASTE(L, d, e) _LANG_##L(d, e)
#define _LANG_EXPAND(L, d, e) _LANG_PASTE(L, d, e)
#define LANG(de, en)        _LANG_EXPAND(LANGUAGE, de, en)

// ── Display ────────────────────────────────────────────────
U8G2_SH1106_128X64_NONAME_F_HW_I2C display(U8G2_R2, U8X8_PIN_NONE);

// ── Anker API ──────────────────────────────────────────────
static const char* API_BASE    = "https://ankerpower-api-eu.anker.com";
static const char* SERVER_PUBKEY_HEX =
    "04c5c00c4f8d1197cc7c3167c52bf7acb054d722f0ef08dcd7e0883236e0d72a3"
    "868d9750cb47fa4619248f3d83f0f662671dadc6e2d31c2f41db0161651c7c076";

// ── Auth-State ─────────────────────────────────────────────
static char g_auth_token[512] = {0};
static char g_gtoken[33]      = {0};
static char g_site_id[64]     = {0};
static bool g_logged_in       = false;

// ── Anzeige-Daten ──────────────────────────────────────────
struct SolixData {
  int  solar_w     = 0;
  int  battery_soc = 0;
  int  bat_power_w = 0;  // + lädt, - entlädt
  int  home_w      = 0;
  int  grid_w      = 0;  // + Bezug, - Einspeisung
  char bat_status[8] = "---";
  bool online      = false;
  bool valid       = false;
};
static SolixData g_data;
static char g_error[48] = {0};
static time_t g_last_fetch_time = 0;  // Zeitpunkt letzter erfolgreicher Abruf

// ══════════════════════════════════════════════════════════
//  CRYPTO HELPERS
// ══════════════════════════════════════════════════════════

static mbedtls_entropy_context   s_entropy;
static mbedtls_ctr_drbg_context  s_ctr_drbg;
static bool s_rng_ready = false;

static void ensureRng() {
  if (s_rng_ready) return;
  mbedtls_entropy_init(&s_entropy);
  mbedtls_ctr_drbg_init(&s_ctr_drbg);
  mbedtls_ctr_drbg_seed(&s_ctr_drbg, mbedtls_entropy_func, &s_entropy, nullptr, 0);
  s_rng_ready = true;
}

// Hex-String → Bytes
static void hexToBytes(const char* hex, uint8_t* out, size_t len) {
  for (size_t i = 0; i < len; i++) {
    char b[3] = { hex[i*2], hex[i*2+1], 0 };
    out[i] = (uint8_t)strtol(b, nullptr, 16);
  }
}

// Bytes → Hex-String (null-terminiert)
static void bytesToHex(const uint8_t* in, size_t len, char* out) {
  for (size_t i = 0; i < len; i++) sprintf(out + i*2, "%02x", in[i]);
  out[len * 2] = 0;
}

/**
 * ECDH P-256:
 *   - Generiert ephemeres Schlüsselpaar
 *   - Berechnet Shared Secret mit Anker-Serverschlüssel
 *   - Gibt client_pub_hex (130 Zeichen + NUL) und shared_secret (32 Bytes) zurück
 */
static bool ecdhComputeShared(char* clientPubHex, uint8_t* sharedSecret) {
  ensureRng();

  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;   // Client Public Key
  mbedtls_ecp_point Qp;  // Server Public Key
  mbedtls_mpi     d;     // Client Private Key
  mbedtls_mpi     z;     // Shared Secret (x-Koordinate)

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_ecp_point_init(&Qp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&z);

  int ret = 0;

  // P-256 Gruppe laden
  ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret) goto done;

  // Ephemeres Schlüsselpaar erzeugen
  ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &s_ctr_drbg);
  if (ret) goto done;

  {
    // Public Key exportieren (unkomprimiert: 04 || X || Y = 65 Bytes)
    uint8_t pubBytes[65];
    size_t  pubLen;
    ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &pubLen, pubBytes, sizeof(pubBytes));
    if (ret || pubLen != 65) goto done;
    bytesToHex(pubBytes, 65, clientPubHex);

    // Server Public Key parsen (130 Hex-Zeichen → 65 Bytes)
    uint8_t serverPubBytes[65];
    hexToBytes(SERVER_PUBKEY_HEX, serverPubBytes, 65);
    ret = mbedtls_ecp_point_read_binary(&grp, &Qp, serverPubBytes, 65);
    if (ret) goto done;
  }

  // ECDH: Shared Secret = d * Qp  →  x-Koordinate
  ret = mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d,
                                     mbedtls_ctr_drbg_random, &s_ctr_drbg);
  if (ret) goto done;

  // Shared Secret als 32-Byte Big-Endian ausgeben
  ret = mbedtls_mpi_write_binary(&z, sharedSecret, 32);

done:
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_point_free(&Qp);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&z);
  return ret == 0;
}

/**
 * AES-256-CBC Verschlüsselung + Base64
 *   Key = sharedSecret (32 Bytes)
 *   IV  = sharedSecret[:16]
 *   Padding = PKCS7
 */
static bool aesEncryptB64(const char* plaintext, const uint8_t* key32,
                           char* outB64, size_t outB64Size) {
  size_t inLen     = strlen(plaintext);
  size_t padded    = ((inLen / 16) + 1) * 16;  // PKCS7 auf 16er-Block
  uint8_t pad_val  = (uint8_t)(padded - inLen);

  uint8_t buf[256] = {0};
  if (padded > sizeof(buf)) return false;
  memcpy(buf, plaintext, inLen);
  for (size_t i = inLen; i < padded; i++) buf[i] = pad_val;

  uint8_t iv[16];
  memcpy(iv, key32, 16);  // IV = erste 16 Bytes des Shared Secret

  uint8_t encrypted[256] = {0};
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int ret = mbedtls_aes_setkey_enc(&aes, key32, 256);
  if (ret == 0)
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT,
                                  padded, iv, buf, encrypted);
  mbedtls_aes_free(&aes);
  if (ret != 0) return false;

  size_t b64Len;
  ret = mbedtls_base64_encode((uint8_t*)outB64, outB64Size, &b64Len,
                               encrypted, padded);
  if (ret != 0) return false;
  outB64[b64Len] = 0;
  return true;
}

// MD5(input) → 32-Zeichen Hex-String
static void md5Hex(const char* input, char* hexOut) {
  uint8_t digest[16];
  mbedtls_md5((const uint8_t*)input, strlen(input), digest);
  bytesToHex(digest, 16, hexOut);
}

// ══════════════════════════════════════════════════════════
//  DISPLAY
// ══════════════════════════════════════════════════════════

static void dispMsg(const char* line1, const char* line2 = nullptr,
                    const char* line3 = nullptr) {
  display.clearBuffer();
  display.setFont(u8g2_font_6x10_tr);
  if (line1) display.drawStr(0, 12, line1);
  if (line2) display.drawStr(0, 26, line2);
  if (line3) display.drawStr(0, 40, line3);
  display.sendBuffer();
}

static void drawSolixData() {
  display.clearBuffer();
  display.setFont(u8g2_font_6x10_tr);

  if (!g_data.valid) {
    display.drawStr(0, 12, "Anker Solix");
    display.drawStr(0, 26, g_error[0] ? g_error : LANG("Verbinde...", "Connecting..."));
    display.sendBuffer();
    return;
  }

  // Zeile 1: Titel + Zeitstempel letzter Abruf
  display.drawStr(0, 10, "Solix 3 Pro");
  if (g_last_fetch_time > 0) {
    char timeBuf[6];
    struct tm* t = localtime(&g_last_fetch_time);
    strftime(timeBuf, sizeof(timeBuf), "%H:%M", t);
    display.drawStr(98, 10, timeBuf);  // 5 Zeichen × 6 px = 30 px, passt ab x=98
  }
  display.drawHLine(0, 13, 128);

  char buf[22];

  // Zeile 2: Solar
  snprintf(buf, sizeof(buf), LANG("Solar: %5dW", "Solar: %5dW"), g_data.solar_w);
  display.drawStr(0, 26, buf);

  // Zeile 3: Batterie / Battery
  snprintf(buf, sizeof(buf), LANG("Akku: %3d%% %s", "Batt: %3d%% %s"),
           g_data.battery_soc, g_data.bat_status);
  display.drawStr(0, 38, buf);

  // Zeile 4: Haus / Home
  snprintf(buf, sizeof(buf), LANG("Haus: %5dW", "Home: %5dW"), g_data.home_w);
  display.drawStr(0, 50, buf);

  // Zeile 5: Netz / Grid
  if (g_data.grid_w >= 0)
    snprintf(buf, sizeof(buf), LANG("Netz: %5dW Bzg", "Grid: %5dW In "), g_data.grid_w);
  else
    snprintf(buf, sizeof(buf), LANG("Netz: %5dW Ein", "Grid: %5dW Out"), -g_data.grid_w);
  display.drawStr(0, 62, buf);

  display.sendBuffer();
}

// ══════════════════════════════════════════════════════════
//  HTTP HELPER
// ══════════════════════════════════════════════════════════

static WiFiClientSecure s_wifiClient;

static bool httpPost(const char* endpoint, const String& body,
                     String& response, bool withAuth = true) {
  String url = String(API_BASE) + "/" + endpoint;
  HTTPClient http;
  http.begin(s_wifiClient, url);
  http.setTimeout(15000);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("model-type",   "DESKTOP");
  http.addHeader("app-name",     "anker_power");
  http.addHeader("os-type",      "android");
  http.addHeader("country",      ANKER_COUNTRY);
  http.addHeader("timezone",     "GMT+01:00");
  if (withAuth && g_logged_in) {
    http.addHeader("gtoken",       g_gtoken);
    http.addHeader("x-auth-token", g_auth_token);
  }

  int code = http.POST(body);
  if (code == 200) {
    response = http.getString();
    http.end();
    return true;
  }
  response = "HTTP " + String(code);
  http.end();
  return false;
}

// ══════════════════════════════════════════════════════════
//  ANKER API
// ══════════════════════════════════════════════════════════

static bool ankerLogin() {
  dispMsg(LANG("Anker Login...", "Anker Login..."),
          LANG("ECDH + AES...",  "ECDH + AES..."));

  // 1) ECDH: Shared Secret berechnen
  char    clientPubHex[131] = {0};
  uint8_t sharedSecret[32]  = {0};
  if (!ecdhComputeShared(clientPubHex, sharedSecret)) {
    strncpy(g_error, LANG("ECDH Fehler", "ECDH Error"), sizeof(g_error));
    return false;
  }

  // 2) Passwort mit AES-256-CBC verschlüsseln
  char encPassword[512] = {0};
  if (!aesEncryptB64(ANKER_PASSWORD, sharedSecret, encPassword, sizeof(encPassword))) {
    strncpy(g_error, LANG("AES Fehler", "AES Error"), sizeof(g_error));
    return false;
  }

  // 3) Timestamp in ms (via NTP)
  time_t now = time(nullptr);
  char transaction[24];
  snprintf(transaction, sizeof(transaction), "%lld000", (long long)now);

  // 4) Login-Request zusammenbauen
  JsonDocument doc;
  doc["ab"]                          = ANKER_COUNTRY;
  doc["client_secret_info"]["public_key"] = clientPubHex;
  doc["enc"]                         = 0;
  doc["email"]                       = ANKER_EMAIL;
  doc["password"]                    = encPassword;
  doc["time_zone"]                   = ANKER_TZ_OFFSET_MS;
  doc["transaction"]                 = transaction;

  String body;
  serializeJson(doc, body);

  dispMsg(LANG("Anker Login...", "Anker Login..."),
          LANG("Sende Anfrage...", "Sending request..."));

  // 5) POST /passport/login
  String response;
  if (!httpPost("passport/login", body, response, false)) {
    snprintf(g_error, sizeof(g_error), "Login: %s", response.c_str());
    return false;
  }

  // 6) Antwort parsen
  JsonDocument resp;
  if (deserializeJson(resp, response) != DeserializationError::Ok) {
    strncpy(g_error, LANG("Login JSON Fehler", "Login JSON Error"), sizeof(g_error));
    return false;
  }

  if (resp["code"] != 0) {
    String msg = resp["msg"] | LANG("unbekannt", "unknown");
    snprintf(g_error, sizeof(g_error), "Login: %s", msg.substring(0,30).c_str());
    return false;
  }

  const char* token   = resp["data"]["auth_token"];
  const char* user_id = resp["data"]["user_id"];

  if (!token || !user_id) {
    strncpy(g_error, LANG("Login: kein Token", "Login: no token"), sizeof(g_error));
    return false;
  }

  strncpy(g_auth_token, token,   sizeof(g_auth_token) - 1);
  md5Hex(user_id, g_gtoken);
  g_logged_in = true;

  Serial.println("[Anker] Login OK");
  Serial.print  ("[Anker] gtoken: "); Serial.println(g_gtoken);
  return true;
}

static bool ankerGetSiteId() {
  String response;
  if (!httpPost("power_service/v1/site/get_site_list", "{}", response)) {
    snprintf(g_error, sizeof(g_error), LANG("SiteList: Fehler", "SiteList: Error"));
    return false;
  }

  JsonDocument doc;
  if (deserializeJson(doc, response) != DeserializationError::Ok) return false;
  if (doc["code"] != 0) return false;

  JsonArray list = doc["data"]["site_list"];
  if (list.isNull() || list.size() == 0) {
    strncpy(g_error, LANG("Keine Site gefunden", "No site found"), sizeof(g_error));
    return false;
  }

  const char* sid = list[0]["site_id"];
  if (!sid) return false;
  strncpy(g_site_id, sid, sizeof(g_site_id) - 1);

  Serial.print("[Anker] site_id: "); Serial.println(g_site_id);
  return true;
}

static bool ankerFetchData() {
  // POST /power_service/v1/site/get_scen_info  {"site_id":"..."}
  String body = "{\"site_id\":\"" + String(g_site_id) + "\"}";
  String response;
  if (!httpPost("power_service/v1/site/get_scen_info", body, response)) {
    snprintf(g_error, sizeof(g_error), LANG("ScenInfo: Fehler", "ScenInfo: Error"));
    return false;
  }

  // Antwort kann groß sein → Filter-Parsing
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, response);
  if (err != DeserializationError::Ok) {
    snprintf(g_error, sizeof(g_error), "JSON: %s", err.c_str());
    return false;
  }

  if (doc["code"] != 0) {
    // Token abgelaufen? → Re-Login
    if (doc["code"] == 401 || doc["code"] == 100053) {
      g_logged_in = false;
    }
    return false;
  }

  JsonObject data = doc["data"];

  // Solarbank-Daten
  JsonObject sb = data["solarbank_info"]["solarbank_list"][0];

  int photovoltaic = atoi(sb["photovoltaic_power"] | "0");
  int battery_pct  = atoi(sb["battery_power"]      | "0");
  int bat_charge_w = atoi(sb["bat_charge_power"]    | "0");
  int output_w     = atoi(sb["output_power"]        | "0");
  int charging_st  = atoi(sb["charging_status"]     | "3");
  bool online      = (strcmp(sb["status"] | "0", "1") == 0);

  // Vorzeichen Bat-Leistung
  int bat_power_w;
  const char* bat_stat;
  if (charging_st == 0) {
    bat_power_w = bat_charge_w;
    bat_stat = LANG("Lad", "Chg");
  } else if (charging_st == 1) {
    bat_power_w = -bat_charge_w;
    bat_stat = LANG("Ent", "Dch");
  } else {
    bat_power_w = 0;
    bat_stat = LANG("Stb", "Stb");
  }

  // Grid
  JsonObject grid = data["grid_info"];
  int grid_to_home   = atoi(grid["grid_to_home_power"]           | "0");
  int pv_to_grid     = atoi(grid["photovoltaic_to_grid_power"]   | "0");
  int grid_w = grid_to_home - pv_to_grid;

  g_data.solar_w     = photovoltaic;
  g_data.battery_soc = battery_pct;
  g_data.bat_power_w = bat_power_w;
  g_data.home_w      = output_w;
  g_data.grid_w      = grid_w;
  g_data.online      = online;
  g_data.valid       = true;
  strncpy(g_data.bat_status, bat_stat, sizeof(g_data.bat_status) - 1);
  g_error[0] = 0;
  g_last_fetch_time = time(nullptr);

  Serial.printf("[Anker] Sol=%dW Bat=%d%%(%s%dW) Home=%dW Grid=%dW\n",
                photovoltaic, battery_pct, bat_stat, bat_charge_w, output_w, grid_w);
  return true;
}

// ══════════════════════════════════════════════════════════
//  WIFI
// ══════════════════════════════════════════════════════════

static void connectWiFi() {
  dispMsg(LANG("WLAN verbinden...", "Connecting WiFi..."), WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 40) {
    delay(500); tries++;
  }
  if (WiFi.status() != WL_CONNECTED) {
    dispMsg(LANG("WLAN Fehler!", "WiFi Error!"),
            LANG("Prüfe config.h", "Check config.h"));
    while (true) delay(1000);
  }
  Serial.print("[WiFi] IP: "); Serial.println(WiFi.localIP());

  // NTP für Zeitstempel
  configTime(3600, 0, "pool.ntp.org", "time.nist.gov");
  dispMsg(LANG("WLAN OK", "WiFi OK"),
          WiFi.localIP().toString().c_str(),
          LANG("Warte auf NTP...", "Waiting for NTP..."));
  // Kurz warten bis NTP synchronisiert
  time_t t = 0;
  for (int i = 0; i < 20 && t < 1000000; i++) { delay(500); t = time(nullptr); }
}

// ══════════════════════════════════════════════════════════
//  SETUP & LOOP
// ══════════════════════════════════════════════════════════

static unsigned long lastFetch = 0;

void setup() {
  Serial.begin(115200);
  display.begin();

  // Startbildschirm
  display.clearBuffer();
  display.setFont(u8g2_font_ncenB10_tr);
  display.drawStr(8, 28, "Anker Solix");
  display.setFont(u8g2_font_6x10_tr);
  display.drawStr(18, 46, "Display v2.0");
  display.sendBuffer();
  delay(1500);

  // TLS: Zertifikat nicht prüfen (vereinfacht, für lokalen Einsatz ok)
  s_wifiClient.setInsecure();

  connectWiFi();

  // Login + erste Daten holen
  if (ankerLogin()) {
    dispMsg(LANG("Login OK!", "Login OK!"),
            LANG("Hole Site-ID...", "Getting Site-ID..."));
    delay(500);
    if (ankerGetSiteId()) {
      dispMsg(LANG("Site gefunden", "Site found"),
              LANG("Lade Daten...", "Loading data..."));
      delay(500);
      ankerFetchData();
    }
  }
  drawSolixData();
  lastFetch = millis();
}

void loop() {
  unsigned long now = millis();
  if (now - lastFetch >= (unsigned long)REFRESH_SEC * 1000UL) {
    lastFetch = now;

    // Bei abgelaufenem Token neu einloggen
    if (!g_logged_in) {
      if (!ankerLogin()) {
        drawSolixData();
        return;
      }
      if (g_site_id[0] == 0) ankerGetSiteId();
    }

    ankerFetchData();
    drawSolixData();
  }
  delay(100);
}
