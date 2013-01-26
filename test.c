/*
 * test.c
 * Nicholas Chaimov
 * CIS 533 Winter 2013
 * 
 * This program performs sanity checks on use of libgcrypt
 * to ensure that the uocrypt library functions are
 * implemented correctly.
 *
 */ 

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include "uocrypt.h"


int main(int argc, char * argv[]) {
	// Silence unused parameter warning
	(void)argc;
	(void)argv;
	
	// Initialize the library
    printf("initializing gcrypt\n");
    uocrypt_initialize_libgcrypt();
    printf("SUCCESS: libgcrypt initialization successful\n");
	
	// Test PBKDF2 with a random salt
    printf("deriving key\n");
	struct uocrypt_key * key = uocrypt_make_key("bad_password", 13, NULL, 0);
	print_key(key);
	if(key != NULL) {
		printf("SUCCESS: key derivation successful\n");
	} else {
	    printf("FAIL: key derivation failure\n");
		return EXIT_FAILURE;
	}
	
	// If we generate another key with the same password and salt, we should
	// get the same key.
	struct uocrypt_key * key2 = uocrypt_make_key("bad_password", 13, key->salt, UOCRYPT_SALT_LEN);
	print_key(key2);
	if(key != NULL) {
		printf("SUCCESS: key derivation successful\n");
	} else {
	    printf("FAIL: key derivation failure\n");
		return EXIT_FAILURE;
	}
	int key_cmp = memcmp(key->key, key2->key, UOCRYPT_KEY_LEN);
	if(key_cmp == 0) {
		printf("SUCCESS: keys match\n");
	} else {
		printf("FAIL: keys don't match\n");
	}
	
	// If we generate another key with the same password but a DIFFERENT
	// salt, we should (with high probability) get different keys.
	struct uocrypt_key * key3 = uocrypt_make_key("bad_password", 13, NULL, 0);
	print_key(key3);
	if(key != NULL) {
		printf("SUCCESS: key derivation successful\n");
	} else {
	    printf("FAIL: key derivation failure\n");
		return EXIT_FAILURE;
	}
	int key_cmp2 = memcmp(key->key, key3->key, UOCRYPT_KEY_LEN);
	if(key_cmp2 != 0) {
		printf("SUCCESS: keys don't match\n");
	} else {
		printf("FAIL: keys match\n");
	}
	
	// If we generate another key with a DIFFERENT password but the SAME
	// salt, we should (with high probability) get different keys.
	struct uocrypt_key * key4 = uocrypt_make_key("let_me_in", 10, key3->salt, UOCRYPT_SALT_LEN);
	print_key(key4);
	if(key != NULL) {
		printf("SUCCESS: key derivation successful\n");
	} else {
	    printf("FAIL: key derivation failure\n");
		return EXIT_FAILURE;
	}
	int key_cmp3 = memcmp(key3->key, key4->key, UOCRYPT_KEY_LEN);
	if(key_cmp3 != 0) {
		printf("SUCCESS: keys don't match\n");
	} else {
		printf("FAIL: keys match\n");
	}
	
	// Encrypt a string with the first key
	const char * input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	printf("Encrypting %s\n", input);
	size_t inlen = strlen(input);
	unsigned char * inbuf = malloc(inlen);
	memcpy(inbuf, input, inlen);
	struct uocrypt_enc_msg * msg = 
		uocrypt_encrypt(inbuf, inlen, key);
	printf("Input:\t");
	for(size_t i = 0; i < inlen; ++i) {
		printf("%02X", inbuf[i]);
	}
	printf("\n");
	print_msg(msg);
	
	// Decrypt the string
	printf("Decrypting\n");
	unsigned char * decrypted = uocrypt_decrypt(msg, key);
	printf("Output:\t");
	for(size_t i = 0; i < msg->txtlen; ++i) {
		printf("%02X", decrypted[i]);
	}
	printf("\n");
	printf("Decrypted to: %*s\n", (int) msg->txtlen, decrypted);
	int msg_cmp = memcmp(inbuf, decrypted, inlen);
	if(msg_cmp == 0) {
		printf("SUCCESS: encryption input and output match\n");
	} else {
		printf("FAIL: encryption input and output differ\n");
	}
	
	// Calculate the HMAC of the message
	unsigned char * hmac = uocrypt_hmac(msg->txt, msg->txtlen, key);
	size_t hmaclen = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
	printf("HMAC:\t");
	for(size_t i = 0; i < hmaclen; ++i) {
		printf("%02X", hmac[i]);
	}
	printf("\n");
	
	// Calculate the HMAC again. Should be the same.
	unsigned char * hmac2 = uocrypt_hmac(msg->txt, msg->txtlen, key);
	printf("HMAC:\t");
	for(size_t i = 0; i < hmaclen; ++i) {
		printf("%02X", hmac2[i]);
	}
	printf("\n");
	int hmac_cmp = memcmp(hmac, hmac2, hmaclen);
	if(hmac_cmp == 0) {
		printf("SUCCESS: HMAC outputs match\n");
	} else {
		printf("FAIL: HMAC outputs differ\n");
	}
	
	free(hmac);
	free(hmac2);
	free(decrypted);
	free(inbuf);
	free(msg->txt);
	free(msg);
	
	free(key);
	free(key2);
	free(key3);
	free(key4);

    return EXIT_SUCCESS;
}
