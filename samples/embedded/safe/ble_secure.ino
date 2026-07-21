// Safe counterpart — MITM-protected BLE pairing, no static passkey.
#include <BLEDevice.h>
#include <BLESecurity.h>

void pair() {
  BLESecurity* sec = new BLESecurity();
  sec->setAuthenticationMode(ESP_LE_AUTH_REQ_SC_MITM_BOND);
  sec->setCapability(ESP_IO_CAP_OUT);
}
