// Intentionally vulnerable — VG-RTOS ISR-body forbidden calls (17f).
volatile int ticks = 0;

void IRAM_ATTR onTimer() {
  Serial.println("tick");   // VG-RTOS-001: I/O in ISR
  int* p = (int*)malloc(4); // VG-RTOS-001: allocation in ISR
  delay(10);                // VG-RTOS-001: blocking in ISR
  ticks++;
}

ISR(TIMER1_OVF_vect) {
  printf("overflow\n");     // VG-RTOS-001: I/O in ISR
}

void setup() {}
void loop() {}
