// Safe counterpart — the shared variable is volatile; a body-local is not
// shared state; a write-only global is not read outside the ISR.
volatile int edgeCount = 0;    // volatile — correct

void IRAM_ATTR onEdge() {
  int scratch = 0;             // body-local, not shared — must NOT be flagged
  scratch++;
  edgeCount++;
}

void loop() {
  if (edgeCount > 10) {
    edgeCount = 0;
  }
}

void setup() {}
