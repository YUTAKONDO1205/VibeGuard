// Intentionally vulnerable — VG-EMB debug-remnant family (17e).
#define DEBUG 1                    // VG-EMB-020: debug on in firmware
#define BYPASS_AUTH 1              // VG-EMB-021: auth bypass flag

const char* password = "loginpw";

void setup() {
  Serial.begin(115200);
}

void loop() {
  Serial.println(password);        // VG-EMB-022: credential to serial
  // TODO: remove before production // VG-EMB-023: removal reminder
}
