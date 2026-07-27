#ifndef CRYPTO_H
#define CRYPTO_H
int crypto_engine_init(void);
int rng_init(void);
int wdt_enable(void);
int secure_boot_verify(void);
#endif
