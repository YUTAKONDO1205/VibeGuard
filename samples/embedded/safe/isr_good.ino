// Safe counterpart — ISR sets a flag only; work deferred to loop().
volatile bool tickFlag = false;

void IRAM_ATTR onTimer() {
  tickFlag = true;
}

void loop() {
  if (tickFlag) {
    tickFlag = false;
    Serial.println("tick handled");
  }
}

void setup() {}
