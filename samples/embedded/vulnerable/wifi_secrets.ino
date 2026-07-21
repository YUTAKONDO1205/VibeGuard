// Intentionally vulnerable Arduino sketch — VG-EMB secrets family (17e).
#include <WiFi.h>

#define WIFI_PASSWORD "s3cr3t-home-net"   // VG-EMB-002: credential in #define

const char* ssid = "HomeNet";

void setup() {
  WiFi.begin("HomeNet", "s3cr3t-home-net"); // VG-EMB-001: literal SSID + password
}

void loop() {}
