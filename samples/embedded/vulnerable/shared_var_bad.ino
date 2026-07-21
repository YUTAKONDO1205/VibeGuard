// Intentionally vulnerable — VG-RTOS-002 (shared ISR variable missing volatile).
int edgeCount = 0;              // non-volatile, shared with the ISR — VG-RTOS-002

void IRAM_ATTR onEdge() {
  edgeCount++;                  // written in the interrupt handler
}

void loop() {
  if (edgeCount > 10) {         // read outside the ISR — may see a stale copy
    edgeCount = 0;
  }
}

void setup() {}
