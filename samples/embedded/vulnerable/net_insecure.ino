// Intentionally vulnerable — VG-EMB comm-downgrade family (17e).
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

WiFiClientSecure client;

void fetch() {
  client.setInsecure();                        // VG-EMB-011: TLS verification off
  HTTPClient http;
  http.begin("http://api.example.com/telemetry"); // VG-EMB-010: cleartext HTTP
  http.GET();
}
