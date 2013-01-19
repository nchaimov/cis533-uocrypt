#ifndef __CRYPT_H__
#define __CRYPT_H__

#define SALT_LEN 16
#define KEY_LEN  32
#define PBKDF2_ITERATIONS 10000

#include <stdbool.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <gcrypt.h>
#pragma GCC diagnostic warning "-Wdeprecated-declarations"

struct uocrypt_key {
	unsigned char salt[SALT_LEN];
	unsigned char key[KEY_LEN];
};

void uocrypt_error(gcry_error_t err);
void uocrypt_initialize_libgcrypt(void);
void * uocrypt_make_salt(void);
struct uocrypt_key * uocrypt_make_key(void * password, 
	size_t passlen, void * salt, size_t saltlen);

#endif
