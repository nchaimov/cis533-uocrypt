#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include "crypt.h"

void print_key(struct uocrypt_key * key) {
	if(key == NULL) {
		printf("Null key\n");
	} else {
		printf("Salt:\t");
		for(size_t i = 0; i < SALT_LEN; ++i) {
			printf("%02X", key->salt[i]);
		}
		printf("\nKey:\t");
		for(size_t i = 0; i < KEY_LEN; ++i) {
			printf("%02X", key->key[i]);
		}
		printf("\n");
	}
}

int main(int argc, char * argv[]) {
	
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
	struct uocrypt_key * key2 = uocrypt_make_key("bad_password", 13, key->salt, SALT_LEN);
	print_key(key2);
	if(key != NULL) {
		printf("SUCCESS: key derivation successful\n");
	} else {
	    printf("FAIL: key derivation failure\n");
		return EXIT_FAILURE;
	}
	int key_cmp = memcmp(key->key, key2->key, KEY_LEN);
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
	int key_cmp2 = memcmp(key->key, key3->key, KEY_LEN);
	if(key_cmp2 != 0) {
		printf("SUCCESS: keys don't match\n");
	} else {
		printf("FAIL: keys match\n");
	}
	
	// If we generate another key with a DIFFERENT password but the SAME
	// salt, we should (with high probability) get different keys.
	struct uocrypt_key * key4 = uocrypt_make_key("let_me_in", 10, key3->salt, SALT_LEN);
	print_key(key4);
	if(key != NULL) {
		printf("SUCCESS: key derivation successful\n");
	} else {
	    printf("FAIL: key derivation failure\n");
		return EXIT_FAILURE;
	}
	int key_cmp3 = memcmp(key3->key, key4->key, KEY_LEN);
	if(key_cmp3 != 0) {
		printf("SUCCESS: keys don't match\n");
	} else {
		printf("FAIL: keys match\n");
	}
	
	
	free(key);
	free(key2);
	free(key3);
	free(key4);

    return EXIT_SUCCESS;
}
