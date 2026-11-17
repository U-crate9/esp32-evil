#include <WiFi.h>
#include <WiFiServer.h>

const char* ssid = "JAM-CTL";
const char* password = "jammer1234";

WiFiServer server(8080);
WiFiClient client;

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  WiFi.mode(WIFI_AP);
  WiFi.softAP(ssid, password);
  server.begin();
  
  Serial.println("[+] Dual-MCU Bridge AP Started: JAM-CTL");
}

void loop() {
  if (!client || !client.connected()) {
    client = server.available();
  }
  
  if (client && client.connected()) {
    while (client.available()) {
      Serial.write(client.read());
    }
  }
  
  while (Serial.available()) {
    char c = Serial.read();
    if (client && client.connected()) {
      client.write(c);
    }
  }
}
