#include <stdio.h>
#include <string.h>
#include <ctype.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static int hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len) {
  if (strlen(hex) != bin_len * 2) return 0;
  for (size_t i = 0; i < bin_len; i++) {
    unsigned int val;
    if (sscanf(hex + i * 2, "%2x", &val) != 1) return 0;
    bin[i] = (unsigned char)val;
  }
  return 1;
}

static void bin_to_hex(const unsigned char *bin, size_t bin_len, char *hex) {
  for (size_t i = 0; i < bin_len; i++) {
    sprintf(hex + i * 2, "%02x", bin[i]);
  }
  hex[bin_len * 2] = '\0';
}

int verify_password(const char *stored_hash) {
  unsigned char password_buf[128];
  unsigned char computed_hash[32];
  char computed_hex[65];
  unsigned char stored_bin[32];
  int match = 1;

  if (fgets((char *)password_buf, sizeof(password_buf), stdin) == NULL) {
    return 0;
  }

  size_t len = strlen((char *)password_buf);
  if (len > 0 && password_buf[len - 1] == '\n') {
    password_buf[len - 1] = '\0';
    len--;
  }

  sha256(password_buf, len, computed_hash);
  bin_to_hex(computed_hash, 32, computed_hex);

  if (!hex_to_bin(stored_hash, stored_bin, 32)) {
    return 0;
  }

  for (int i = 0; i < 32; i++) {
    if (computed_hash[i] != stored_bin[i]) {
      match = 0;
    }
  }

  return match;
}
