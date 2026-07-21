// Intentionally vulnerable — VG-EMB-031 (peripheral used before begin()).
void setup() {
  Serial.println("booting...");   // VG-EMB-031: printed before Serial.begin()
  Serial.begin(115200);
  Wire.requestFrom(0x40, 2);      // VG-EMB-031: read before Wire.begin()
  Wire.begin();
}

void loop() {}
