/*
 * uocrypt.h
 * Nicholas Chaimov
 * CIS 533 Winter 2013
 *
 * uocrypt encapsulates libgcrypt functions
 *
 */ 


#ifndef __CRYPT_H__
#define __CRYPT_H__

#define UOCRYPT_SALT_LEN 16
#define UOCRYPT_KEY_LEN  32
#define UOCRYPT_PBKDF2_ITERATIONS 64000
#define UOCRYPT_DERIV GCRY_KDF_PBKDF2
#define UOCRYPT_DERIV_SUBALGO GCRY_MD_SHA512
#define UOCRYPT_CIPHER GCRY_CIPHER_AES256
#define UOCRYPT_BLOCK_LEN 16
#define UOCRYPT_MODE GCRY_CIPHER_MODE_CFB
#define UOCRYPT_HMAC_HASH GCRY_MD_SHA512

#include <stdbool.h>
	
// I don't care that libgcrypt itself uses deprecated functions,
// since there's nothing I can do about it.
	
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <gcrypt.h>
#pragma GCC diagnostic warning "-Wdeprecated-declarations"

struct uocrypt_key {
	unsigned char salt[UOCRYPT_SALT_LEN];
	unsigned char key[UOCRYPT_KEY_LEN];
};

struct uocrypt_enc_msg {
	unsigned char iv[UOCRYPT_BLOCK_LEN];
	size_t txtlen;
	unsigned char * txt;
};

void uocrypt_error(gcry_error_t err);

void uocrypt_initialize_libgcrypt(void);

void * uocrypt_make_salt(void);

struct uocrypt_key * uocrypt_make_key(void * password, 
	size_t passlen, void * salt, size_t saltlen);

struct uocrypt_enc_msg * uocrypt_encrypt(unsigned char * in, size_t inlen, 
	struct uocrypt_key * key);

unsigned char * uocrypt_decrypt(struct uocrypt_enc_msg * msg, 
	struct uocrypt_key * key);

unsigned char * uocrypt_hmac(unsigned char * in, size_t inlen, 
	struct uocrypt_key * key);

size_t uocrypt_hmac_len(void);

void print_key(struct uocrypt_key * key);

void print_msg(struct uocrypt_enc_msg * msg);


#endif
