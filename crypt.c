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
	unsigned char * buf = malloc(UOCRYPT_SALT_LEN);
	// GCRY_STRONG_RANDOM is for "session keys and similar purposes"
	gcry_randomize(buf, UOCRYPT_SALT_LEN, GCRY_STRONG_RANDOM);
	return buf;
}

// Create a key from a password via PBKDF2. If a salt is provided, it is used,
// otherwise a random salt is generated. saltlen is ignored if no salt is
// provided.
struct uocrypt_key * uocrypt_make_key(void * password, size_t passlen, void * salt, size_t saltlen) {
	if(password == NULL) {
		fprintf(stderr, "Error: uocrypt_make_key 'password' was NULL.\n");
		return NULL;
	}	
	
	bool our_salt = false;
	if(salt == NULL) {
		salt = uocrypt_make_salt();
		saltlen = UOCRYPT_SALT_LEN;
		our_salt = true;
	}
	unsigned char * keybuf = malloc(UOCRYPT_KEY_LEN);
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
	
	struct uocrypt_key * key = malloc(sizeof(struct uocrypt_key));
	memcpy(key->salt, salt, UOCRYPT_SALT_LEN);
	memcpy(key->key, keybuf, UOCRYPT_KEY_LEN);
	
	if(our_salt) {
		free(salt);
	}
	free(keybuf);
	return key;
}

// Encrypt a message with the given key and a randomly
// generated initialization vector
struct uocrypt_enc_msg * uocrypt_encrypt(unsigned char * in, size_t inlen, struct uocrypt_key * key) {
	if(in == NULL) {
		fprintf(stderr, "Error: uocrypt_encrypt 'in' was NULL.\n");
		return NULL;
	}
	if(key == NULL) {
		fprintf(stderr, "Error: uocrypt_encrypt 'key' was NULL.\n");
		return NULL;
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
	
	msg->txt = malloc(inlen);
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

// Decrypt a message with the given key.
unsigned char * uocrypt_decrypt(struct uocrypt_enc_msg * msg, struct uocrypt_key * key) {
	if(msg == NULL) {
		fprintf(stderr, "Error: uocrypt_decrypt 'msg' was NULL.\n");
		return NULL;
	}
	if(key == NULL) {
		fprintf(stderr, "Error: uocrypt_decrypt 'key' was NULL.\n");
		return NULL;
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
	unsigned char * out = malloc(msg->txtlen);
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

unsigned char * uocrypt_hmac(unsigned char * in, size_t inlen, struct uocrypt_key * key) {
	if(in == NULL) {
		fprintf(stderr, "Error: uocrypt_hmac 'in' was NULL.\n");
		return NULL;
	}
	if(key == NULL) {
		fprintf(stderr, "Error: uocrypt_hmac 'key' was NULL.\n");
		return NULL;
	}

	gcry_md_hd_t hh;
	gcry_error_t err;
	
	// Open the hash handle
	err = gcry_md_open(&hh, UOCRYPT_HMAC_HASH, GCRY_MD_FLAG_HMAC);
	if(err) {
		uocrypt_error(err);
		return NULL;
	}
					
	// Set the HMAC key
	err = gcry_md_setkey(hh, key->key, UOCRYPT_KEY_LEN);
	if(err) {
		uocrypt_error(err);
		return NULL;
	}
	
	// Hash the message
	gcry_md_write(hh, in, inlen);
	gcry_md_final(hh);
	
	// Read the hash out of the hash handle
	unsigned char * hash = gcry_md_read(hh, 0);
	
	// Copy the hash to our own memory, as the hash returned
	// by gcry_md_read will be freed when the handle is closed.
	size_t dlen = gcry_md_get_algo_dlen(UOCRYPT_HMAC_HASH);
	unsigned char * out = malloc(dlen);
	memcpy(out, hash, dlen);
	
	gcry_md_close(hh);
	return out;
}

size_t uocrypt_hmac_len(void) {
	return gcry_md_get_algo_dlen(UOCRYPT_HMAC_HASH);
}

void print_key(struct uocrypt_key * key) {
	if(key == NULL) {
		printf("Null key\n");
	} else {
		printf("Salt:\t");
		for(size_t i = 0; i < UOCRYPT_SALT_LEN; ++i) {
			printf("%02X", key->salt[i]);
		}
		printf("\nKey:\t");
		for(size_t i = 0; i < UOCRYPT_KEY_LEN; ++i) {
			printf("%02X", key->key[i]);
		}
		printf("\n");
	}
}

void print_msg(struct uocrypt_enc_msg * msg) {
	if(msg == NULL) {
		printf("Null message.\n");
	} else {
		printf("IV:\t");
		for(size_t i = 0; i < UOCRYPT_BLOCK_LEN; ++i) {
			printf("%02X", msg->iv[i]);
		}
		printf("\nText:\t");
		for(size_t i = 0; i < msg->txtlen; ++i) {
			printf("%02X", msg->txt[i]);
		}
		printf("\n");
	}
}
