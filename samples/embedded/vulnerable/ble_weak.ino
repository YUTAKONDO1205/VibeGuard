// Intentionally vulnerable — VG-EMB BLE weak-pairing (17e).
#include <BLEDevice.h>
#include <BLESecurity.h>

void pair() {
  BLESecurity* sec = new BLESecurity();
  sec->setStaticPIN(123456);          // VG-EMB-003: static BLE passkey
  sec->setAuthenticationMode(ESP_LE_AUTH_BOND); // VG-EMB-012: Just Works
}
