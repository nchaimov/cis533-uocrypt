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

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

// Create a random salt.
// The caller owns the salt and must ensure that it is freed when
// it is no longer needed.
void * uocrypt_make_salt(void) {
	unsigned char * buf =
		(unsigned char *) malloc(UOCRYPT_SALT_LEN * sizeof(unsigned char));
	// GCRY_STRONG_RANDOM is for "session keys and similar purposes"
	gcry_randomize(buf, UOCRYPT_SALT_LEN, GCRY_STRONG_RANDOM);
	return buf;
}

// Create a key from a password via PBKDF2. If a salt is provided, it is used,
// otherwise a random salt is generated. saltlen is ignored if no salt is
// provided.
struct uocrypt_key * uocrypt_make_key(void * password, size_t passlen, void * salt, size_t saltlen) {
	bool our_salt = false;
	if(salt == NULL) {
		salt = uocrypt_make_salt();
		saltlen = UOCRYPT_SALT_LEN;
		our_salt = true;
	}
	unsigned char * keybuf  = 
		(unsigned char *) malloc(UOCRYPT_KEY_LEN * sizeof(unsigned char));
	gpg_error_t err;
	
	err = gcry_kdf_derive(password, passlen, UOCRYPT_DERIV,
		UOCRYPT_DERIV_SUBALGO, salt, saltlen, UOCRYPT_PBKDF2_ITERATIONS,
		UOCRYPT_KEY_LEN, keybuf);
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
	memcpy(key->salt, salt, UOCRYPT_SALT_LEN);
	memcpy(key->key, keybuf, UOCRYPT_KEY_LEN);
	
	if(our_salt) {
		free(salt);
	}
	free(keybuf);
	return key;
}

struct uocrypt_enc_msg * uocrypt_encrypt(unsigned char * in, size_t inlen, struct uocrypt_key * key) {
	if(in == NULL) {
		fprintf(stderr, "Error: uocrypt_encrypt 'in' was NULL.\n");
		return NULL;
	}
	if(key == NULL) {
		fprintf(stderr, "Error: uocrypt_encrypt 'key' was NULL.\n");
	}
	
	gcry_error_t err;
	gcry_cipher_hd_t cipher;
	
	// Open the cipher
	err = gcry_cipher_open(&cipher, UOCRYPT_CIPHER, UOCRYPT_MODE, 0);
	if(err) {
		uocrypt_error(err);
		return NULL;
	}
	
	// Set the cipher key
	err = gcry_cipher_setkey(cipher, key->key, UOCRYPT_KEY_LEN);
	if(err) {
		uocrypt_error(err);
		gcry_cipher_close(cipher);
		return NULL;
	}
	
	// Set the initialization vector. This needs to be the same as
	// the block length of the cipher.
	struct uocrypt_enc_msg * msg = malloc(sizeof(struct uocrypt_enc_msg));
	// The manual indicates that gcry_create_nonce
	// "may also be used for initialization vectors"
	gcry_create_nonce(msg->iv, UOCRYPT_BLOCK_LEN);
	err = gcry_cipher_setiv(cipher, msg->iv, UOCRYPT_BLOCK_LEN);
	if(err) {
		uocrypt_error(err);
		gcry_cipher_close(cipher);
		free(msg);
		return NULL;
	}
	
	msg->txt = malloc(inlen * sizeof(unsigned char));
	msg->txtlen = inlen;
	err = gcry_cipher_encrypt(cipher, msg->txt, inlen, in, inlen);
	if(err) {
		uocrypt_error(err);
		gcry_cipher_close(cipher);
		free(msg->txt);
		free(msg);
		return NULL;
	}
	
	gcry_cipher_close(cipher);
	
	return msg;
}

unsigned char * uocrypt_decrypt(struct uocrypt_enc_msg * msg, struct uocrypt_key * key) {
	if(msg == NULL) {
		fprintf(stderr, "Error: uocrypt_decrypt 'msg' was NULL.\n");
		return NULL;
	}
	if(key == NULL) {
		fprintf(stderr, "Error: uocrypt_decrypt 'key' was NULL.\n");
	}
	
	gcry_error_t err;
	gcry_cipher_hd_t cipher;
	
	// Open the cipher
	err = gcry_cipher_open(&cipher, UOCRYPT_CIPHER, UOCRYPT_MODE, 0);
	if(err) {
		uocrypt_error(err);
		return NULL;
	}
	
	// Set the cipher key
	err = gcry_cipher_setkey(cipher, key->key, UOCRYPT_KEY_LEN);
	if(err) {
		uocrypt_error(err);
		gcry_cipher_close(cipher);
		return NULL;
	}
	
	// Set the initialization vector
	err = gcry_cipher_setiv(cipher, msg->iv, UOCRYPT_BLOCK_LEN);
	if(err) {
		uocrypt_error(err);
		gcry_cipher_close(cipher);
		return NULL;
	}
	
	// Decrypt the message
	unsigned char * out = malloc(msg->txtlen * sizeof(unsigned char));
	err = gcry_cipher_decrypt(cipher, out, msg->txtlen, msg->txt, 
		msg->txtlen);
	if(err) {
		uocrypt_error(err);
		free(out);
		gcry_cipher_close(cipher);
		return NULL;
	}
	
	gcry_cipher_close(cipher);
	return out;
}