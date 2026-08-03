#ifndef SSL_WRAP_H
#define SSL_WRAP_H

/* The project declares its OWN small surface. It declares nothing named SSL_*. */
const char *wrap_cipher_name(void *conn);
const char *wrap_cipher_version(void *conn);
int wrap_start(void *conn);

#endif
