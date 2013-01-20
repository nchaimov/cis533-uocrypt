#ifndef __UOUTIL_H__
#define __UOUTIL_H__

#include "crypt.h"

#define MAX_FILENAME_LEN 255
#define EXTENSION ".uo"
#define IDENTIFIER "UOEN"

extern char * progname;

struct uoenc_file_header {
	char identifier[4];
	unsigned char salt[UOCRYPT_SALT_LEN];
	unsigned char iv[UOCRYPT_BLOCK_LEN];
	size_t hmac_len;
	size_t txt_len;
};

void uoenc_err(const char * err);
struct uoenc_file_header * uoenc_make_header(void);

#endif
