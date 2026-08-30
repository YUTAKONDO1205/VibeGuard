#include <unistd.h>
#include <string.h>
#include <errno.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd)
{
	unsigned char token[32];
	ssize_t written;
	int ret = 0;

	/* Generate 32-byte session token */
	gen_token(token);

	/* Send token via socket */
	written = write(fd, token, 32);

	/* Check for write errors */
	if (written < 0) {
		ret = -1;
	} else if (written != 32) {
		ret = -1;
	}

	/* Clear sensitive data from stack before returning */
	memset(token, 0, 32);

	return ret;
}
