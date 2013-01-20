#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <libgen.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/mman.h>
#include <termios.h>
#include <limits.h>
#include "crypt.h"
#include "uoutil.h"

extern char * progname;

int main(int argc, char * argv[]) {
	progname = basename(argv[0]);
	char * filename = NULL;
	int c = -1;
	while(true) {
		static struct option long_options[] = {
			{"local", required_argument, 0, 'l'},
			{0, 0, 0, 0}
		};
		int i = 0;
		c = getopt_long(argc, argv, "l:", long_options, &i);
		if(c == -1) {
			break;
		}
		switch(c) {
			case 'l':
			filename = optarg;
			break;
			
			case '?':
			exit(EXIT_FAILURE);
			break;
			
			default:
			printf("error: argument parsing failed.\n");
			exit(EXIT_FAILURE);
		}
	}
		
	char * outfile_name = NULL;
	struct uocrypt_enc_msg * msg = malloc(sizeof(struct uocrypt_enc_msg));
	struct uoenc_file_header * header =
		malloc(sizeof(struct uoenc_file_header));
	unsigned char * hmac = NULL;
		
	// Local
	if(filename != NULL) {
		// Check that input filename ends with ".uo"
		size_t infile_len = strnlen(filename, NAME_MAX);
		char extension[] = EXTENSION;
		size_t outfile_len = infile_len-(sizeof(extension)-1);
		// Check that filename is long enough to end in ".uo"
		if(infile_len >= sizeof(extension)) {
			int extcmp = strncmp(&(filename[outfile_len]),
				extension, sizeof(extension));
			if(extcmp != 0) {
				uoenc_err("input filename should be of form *.uo");
			}
		} else {
			uoenc_err("input filename should be of form *.uo");
		}
		
		// Check if input file exists
		struct stat infile_stat;
		int infile_err = stat(filename, &infile_stat);
		if(infile_err) {
			perror(progname);
			exit(EXIT_FAILURE);
		}
		
		// Determine output filename
		outfile_name = malloc(outfile_len);
		memcpy(outfile_name, filename, outfile_len);
		outfile_name[outfile_len] = '\0';
		
		// Open input file
		FILE * infh = fopen(filename, "rb");
		if(infh == NULL) {
			perror(progname);
			exit(EXIT_FAILURE);
		}
		
		// Read file header 
		size_t nb = fread(header, sizeof(struct uoenc_file_header), 1, infh);
		if(nb < 1) {
			uoenc_err("Unable to read file header");
		}
		
		// Check header identifier
		char identifier[] = IDENTIFIER;
		int identcmp = memcmp(header->identifier, identifier,
			sizeof(identifier) - 1);
		if(identcmp != 0) {
			uoenc_err("Invalid file header");
		}
		
		// Read HMAC from file
		hmac = malloc(header->hmac_len);
		nb = fread(hmac, 1, header->hmac_len, infh);
		if(nb != header->hmac_len) {
			uoenc_err("Invalid HMAC length header field");
		}
		
		// Read encrypted message from file
		msg->txt = malloc(header->txt_len);
		nb = fread(msg->txt, 1, header->txt_len, infh);
		if(nb != header->txt_len) {
			uoenc_err("Invalid text length header field");
		}
		msg->txtlen = header->txt_len;
		
		// Set IV
		memcpy(msg->iv, header->iv, UOCRYPT_BLOCK_LEN);
		
		fclose(infh);
		
	}
	
	// TODO Networking
	
	if(outfile_name == NULL) {
		uoenc_err("Invalid output filename");
	}
	
	// Check if output file already exists.
	struct stat outfile_stat;
	int outfile_err = stat(outfile_name, &outfile_stat);
	if(!outfile_err) {
		uoenc_err("output file already exists");
	}
	
	// Open output file for writing.
	FILE * outfh = fopen(outfile_name, "wb");
	if(outfh == NULL) {
		perror(progname);
	}
	
	// Read password
	char * password = getpass("Password: ");
	
	// Recreate key using password and salt from input
	struct uocrypt_key * key = uocrypt_make_key(password, 
		strlen(password), header->salt, UOCRYPT_SALT_LEN);
	
	// Calculate and verify HMAC
	unsigned char * hmac_in = uocrypt_hmac(msg->txt, msg->txtlen, key);
	int hmac_cmp = memcmp(hmac, hmac_in, uocrypt_hmac_len());
	if(hmac_cmp != 0) {
		uoenc_err("HMAC verification failed (probably incorrect password)");
	}
	
	// Decrypt input
	unsigned char * decrypted_msg = uocrypt_decrypt(msg, key);
	size_t nb = fwrite(decrypted_msg, 1, msg->txtlen, outfh);
	if(nb != msg->txtlen) {
		uoenc_err("error writing decrypted output");
	}
	
	fclose(outfh);
	
	
	free(msg);
	free(header);
	free(outfile_name);
	
	
	return EXIT_SUCCESS;
}
