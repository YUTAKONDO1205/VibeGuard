/* Safe counterpart — O_DIRECT paired with O_SYNC for durability. */
#include <fcntl.h>

int log_open(const char *path) {
  return open(path, O_WRONLY | O_CREAT | O_DIRECT | O_SYNC, 0644);
}
