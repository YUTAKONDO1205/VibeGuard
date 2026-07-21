// Safe counterpart — debug off, gated by build type, no bypass.
#define DEBUG 0

void setup() {
  Serial.begin(115200);
#ifdef DEBUG
#if DEBUG
  Serial.println("debug build");
#endif
#endif
}

void loop() {}
