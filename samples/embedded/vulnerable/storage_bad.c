/* Intentionally vulnerable — VG-RTOS-004 (O_DIRECT without sync). */
#include <fcntl.h>

int log_open(const char *path) {
  return open(path, O_WRONLY | O_CREAT | O_DIRECT, 0644); /* VG-RTOS-004 */
}
