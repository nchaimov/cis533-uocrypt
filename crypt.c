#include "crypt.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <gcrypt.h>
#pragma GCC diagnostic warning "-Wdeprecated-declarations"

void uocrypt_error(gcry_error_t err) {
	fprintf(stderr, "error: %s: %s\n", gcry_strsource(err), 
		gcry_strerror(err));
}

// This is from the libgcrypt manual, section 2.4, "Initializing the library"
// Call this function before anything else that uses gcrypt
void uocrypt_initialize_libgcrypt(void) {
    if(!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "Error: libgcrypt header and library versions do not match.\n");
        exit(EXIT_FAILURE);
    }

    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

// Create a random salt.
// The caller owns the salt and must ensure that it is freed when
// it is no longer needed.
void * uocrypt_make_salt(void) {
	unsigned char * buf =
		(unsigned char *) malloc(SALT_LEN * sizeof(unsigned char));
	// GCRY_STRONG_RANDOM is for "session keys and similar purposes"
	gcry_randomize(buf, SALT_LEN, GCRY_STRONG_RANDOM);
	return buf;
}

// Create a key from a password via PBKDF2 with a random salt
// Caller must free key.
struct uocrypt_key * uocrypt_make_key(void * password, size_t passlen, void * salt, size_t saltlen) {
	bool our_salt = false;
	if(salt == NULL) {
		salt = uocrypt_make_salt();
		saltlen = SALT_LEN;
		our_salt = true;
	}
	unsigned char * keybuf  = 
		(unsigned char *) malloc(KEY_LEN * sizeof(unsigned char));
	gpg_error_t err;
	
	err = gcry_kdf_derive(password, passlen, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, saltlen, PBKDF2_ITERATIONS, KEY_LEN, keybuf);
	if(err) {
		uocrypt_error(err);
		if(our_salt) {
			free(salt);
		}
		free(keybuf);
		return NULL;
	}
	
	struct uocrypt_key * key = 
		(struct uocrypt_key *) malloc(sizeof(struct uocrypt_key));
	memcpy(key->salt, salt, SALT_LEN);
	memcpy(key->key, keybuf, KEY_LEN);
	
	if(our_salt) {
		free(salt);
	}
	free(keybuf);
	return key;
}
