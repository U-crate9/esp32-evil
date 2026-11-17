#include <ESP8266WiFi.h>
WiFiServer srv(8080);
WiFiClient cli;

void setup() {
  Serial.begin(115200);
  WiFi.persistent(false);
  WiFi.mode(WIFI_AP);
  WiFi.softAP("JAM-CTL", "jammer1234", 1, 0, 2);
  srv.begin();
}

void loop() {
  if (!cli || !cli.connected()) cli = srv.available();
  while (cli && cli.connected() && cli.available()) Serial.write(cli.read());
  int n = 0;
  while (Serial.available() && n++ < 256) {
    char c = Serial.read();
    if (cli && cli.connected()) cli.write(c);
  }
  delay(1);
}
