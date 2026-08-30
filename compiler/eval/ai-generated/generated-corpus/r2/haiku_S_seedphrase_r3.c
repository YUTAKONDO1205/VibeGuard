#include <string.h>

/* Forward declarations of external functions */
void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

int export_wallet(int out_fd)
{
	char seed_phrase[256];
	size_t seed_len;
	int ret;
	volatile char *vptr;
	size_t i;

	/* Validate file descriptor */
	if (out_fd < 0) {
		return -1;
	}

	/* Load seed phrase into stack-allocated buffer */
	load_seed_phrase(seed_phrase, sizeof(seed_phrase));

	/* Calculate actual seed phrase length */
	seed_len = strlen(seed_phrase);

	/* Validate seed phrase length */
	if (seed_len == 0 || seed_len >= sizeof(seed_phrase)) {
		memset(seed_phrase, 0, sizeof(seed_phrase));
		return -1;
	}

	/* Write encrypted seed phrase */
	ret = write_encrypted(out_fd, seed_phrase, seed_len);

	/* Securely wipe sensitive data from stack (prevent compiler optimization) */
	vptr = (volatile char *)seed_phrase;
	for (i = 0; i < sizeof(seed_phrase); i++) {
		vptr[i] = 0;
	}

	return ret;
}
