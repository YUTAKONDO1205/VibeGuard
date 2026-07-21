// Safe counterpart — TLS with a pinned CA, https endpoint.
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

extern const char* root_ca_pem;
WiFiClientSecure client;

void fetch() {
  client.setCACert(root_ca_pem);
  HTTPClient http;
  http.begin(client, "https://api.example.com/telemetry");
  http.GET();
}
