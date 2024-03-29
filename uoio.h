/*
 * uoio.h
 * Nicholas Chaimov
 * CIS 533 Winter 2013
 *
 * File and network I/O functions
 *
 */ 


#ifndef __UOIO_H__
#define __UOI_H__

#include "uocrypt.h"
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

#define EXTENSION ".uo"
#define IDENTIFIER "UOEN"
#define FILENAME_LEN 255

#ifndef PASS_MAX
#define PASS_MAX 255
#endif

extern char * progname;

// These structs are packed because they will be used directly
// for file contents and network packets, and we don't want any
// padding.
struct __attribute__ ((__packed__)) uoenc_file_header {
	char identifier[4];
	unsigned char salt[UOCRYPT_SALT_LEN];
	unsigned char iv[UOCRYPT_BLOCK_LEN];
	uint32_t hmac_len;
	uint32_t txt_len;
};

struct __attribute__ ((__packed__)) uoenc_network_packet {
	uint32_t packet_len;
	char filename[FILENAME_LEN];
	struct uoenc_file_header header;
	char body[0]; // Don't know size ahead of time
};

// Print an error and exit
void uoenc_err(const char * err) __attribute__ ((__noreturn__));

// Network functions
bool uoenc_parse_packet(struct uoenc_network_packet * in, 
	struct uocrypt_enc_msg * msg_out, unsigned char * salt, 
	unsigned char * hmac, char * filename);
struct uoenc_network_packet * uoenc_create_packet(struct uocrypt_key * key_in, 
	struct uocrypt_enc_msg * msg_in, unsigned char * hmac, char * filename);
bool uoenc_send_packet(int socket, struct uoenc_network_packet * packet);
struct uoenc_network_packet * uoenc_recv_packet(int socket);
	
// File functions
char * uoenc_outfile_name(char * infile_name);
struct uoenc_file_header * uoenc_make_header(void);
bool uoenc_read_uo_file(FILE * fh, struct uocrypt_enc_msg * msg_out, 
	unsigned char * salt, unsigned char * hmac);
bool uoenc_write_uo_file(FILE * fh, struct uocrypt_key * key_in, 
	struct uocrypt_enc_msg * msg_in, unsigned char * hmac_in);

#endif
