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
	bool local = false;
	char * addr_str = NULL;
	char * filename = NULL;
	int c = -1;
	int opt;
	while(true) {
		static struct option long_options[] = {
			{"local", no_argument, 0, 'l'},
			{"daemon", required_argument, 0, 'd'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "-ld:", long_options, &opt);
		if(c == -1) {
			break;
		}
		switch(c) {
			case 'l':
			local = true;
			break;
			
			case 'd':
			addr_str = optarg;
			break;
			
			case '?':
			exit(EXIT_FAILURE);
			break;
			
			case '\1':
			if(filename == NULL) {
				filename = optarg;
			} else {
				uoenc_err("only one filename can be provided.");
			}
			break;
			
			default:
			uoenc_err("argument parsing failed.");
		}
	}
		
	if(local && addr_str) {
		uoenc_err("can't use both -l and -d simultaneously.");
	}
	
	if((!local && !addr_str) || !filename) {
		fprintf(stderr, "usage: %s filename [-d address] [-l]\n", progname);
		exit(EXIT_FAILURE);
	}
	
	// Check if input file exists
	struct stat infile_stat;
	int infile_err = stat(filename, &infile_stat);
	if(infile_err) {
		perror(progname);
		exit(EXIT_FAILURE);
	}
	
	// Determine output filename
	char * outfile_name = uoenc_outfile_name(filename);
	
	
	// Check if output file already exists
	if(local) {
		struct stat outfile_stat;
		int outfile_err = stat(outfile_name, &outfile_stat);
		if(outfile_err == 0) {
			uoenc_err("Output file already exists.");
		}
	}
	
	// Open input file
	int infd = open(filename, O_RDONLY);
	if(infd == -1) {
		perror(progname);
		exit(EXIT_FAILURE);
	}
	
	// mmap input file
	char * input_buf = mmap(NULL, infile_stat.st_size, PROT_READ,
		MAP_SHARED | MAP_FILE, infd, 0);
	if(input_buf == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}
	
	// Encrypt the input
	uocrypt_initialize_libgcrypt();
	char * password = getpass("Password: ");
	struct uocrypt_key * key = uocrypt_make_key(password, 
		strnlen(password, PASS_MAX), NULL, 0);
	struct uocrypt_enc_msg * msg = uocrypt_encrypt((unsigned char *)input_buf,
		infile_stat.st_size, key);
	
	// Calculate the HMAC
	unsigned char * hmac = uocrypt_hmac(msg->txt, msg->txtlen, key);
	
	// Fill in header
	struct uoenc_file_header * header = uoenc_make_header();
	memcpy(header->salt, key->salt, UOCRYPT_SALT_LEN);
	memcpy(header->iv, msg->iv, UOCRYPT_BLOCK_LEN);
	header->hmac_len = uocrypt_hmac_len();
	header->txt_len = infile_stat.st_size;
	
	if(local) {
		// Open output file
		FILE * outf = fopen(outfile_name, "wb");
		if(outf == NULL) {
			perror(progname);
			exit(EXIT_FAILURE);
		}
		// Write header
		fwrite(header, 1, sizeof(struct uoenc_file_header), outf);
		// Write HMAC
		fwrite(hmac, 1, header->hmac_len, outf);
		// Write encrypted text
		fwrite(msg->txt, 1, header->txt_len, outf);
		fclose(outf);
	} else {
		// TODO Handle networking
	}
	
	
	free(header);
	free(hmac);
	free(key);
	free(msg->txt);
	free(msg);
	
	
	munmap(input_buf, infile_stat.st_size);
	close(infd);
	
	return EXIT_SUCCESS;
}
