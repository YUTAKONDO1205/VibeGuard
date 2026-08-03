#include "ssl_wrap.h"
#include <openssl/ssl.h>

/* Three `return <SSL_ call>;` lines. Before the PROTOTYPE repair these read as
   declarations of SSL_get_cipher_name / SSL_get_cipher_version / SSL_get_servername,
   which manufactured the `SSL_*` namespace out of call sites alone. */
const char *wrap_cipher_name(void *conn)
{
	return SSL_get_cipher_name(conn);
}

const char *wrap_cipher_version(void *conn)
{
	return SSL_get_cipher_version(conn);
}

const char *wrap_servername(void *conn)
{
	return SSL_get_servername(conn, 0);
}

/* Ordinary OpenSSL usage. Every one of these is real and declared in a system
   header. None may be reported. */
int wrap_start(void *ctx)
{
	void *ssl = SSL_new(ctx);
	if (!ssl)
		return 0;
	SSL_set_connect_state(ssl);
	return SSL_do_handshake(ssl);
}
