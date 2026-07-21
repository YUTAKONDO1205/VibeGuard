// Safe counterpart for the init-order family. pinMode lives in a helper and
// pins are passed as parameters — a legitimate form that must NOT be flagged.
// EMB-030 (digitalWrite before pinMode) is DROPPED precisely because this and
// the glitch-free-init idiom are lexically indistinguishable from the bug; the
// only decidable init-order rule shipped is EMB-031 (use-before-begin), which
// this file does not trigger (no Serial/SD/Wire/SPI use before begin).
void configurePin(int pin) {
  pinMode(pin, OUTPUT);
}

void setup() {
  configurePin(13);
  digitalWrite(13, HIGH);
}

void loop() {}
