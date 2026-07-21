// Safe counterpart — credentials provisioned at runtime, not baked in.
#include <WiFi.h>
#include <Preferences.h>

Preferences prefs;

void setup() {
  prefs.begin("net", true);
  String ssid = prefs.getString("ssid");
  String pw = prefs.getString("pw");
  WiFi.begin(ssid.c_str(), pw.c_str());
}

void loop() {}
