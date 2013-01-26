/*
 * uodec.c
 * Nicholas Chaimov
 * CIS 533 Winter 2013
 *
 * Decryption utility. Either decrypts a local file
 * or listens for a message from uoenc over the network.
 *
 */ 


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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include "uocrypt.h"
#include "uoio.h"

extern char * progname;

int main(int argc, char * argv[]) {
	progname = basename(argv[0]);
	char * filename = NULL;
	int c = -1;
	int sock = -1;
	char * port = NULL;
	
	// Process command line arguments
	while(true) {
		static struct option long_options[] = {
			{"local", required_argument, 0, 'l'},
			{0, 0, 0, 0}
		};
		int i = 0;
		c = getopt_long(argc, argv, "-l:", long_options, &i);
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
			
			// Process bare arguments
			case '\1':
			if(port == NULL) {
				port = optarg;
			} else {
				uoenc_err("only one port can be provided.");
			}
			break;
			
			default:
			printf("error: argument parsing failed.\n");
			exit(EXIT_FAILURE);
		}
	}
		
	char * outfile_name = NULL;
	struct uocrypt_enc_msg * msg = malloc(sizeof(struct uocrypt_enc_msg));
	unsigned char * salt = malloc(UOCRYPT_SALT_LEN);
	unsigned char * hmac = malloc(uocrypt_hmac_len());
		
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
		outfile_name = malloc(outfile_len+1);
		memcpy(outfile_name, filename, outfile_len);
		outfile_name[outfile_len] = '\0';
				
		// Open input file
		FILE * infh = fopen(filename, "rb");
		if(infh == NULL) {
			perror(progname);
			exit(EXIT_FAILURE);
		}
				
		// Read file
		uoenc_read_uo_file(infh, msg, salt, hmac); 
				
		fclose(infh);
	} else {
		// Network
		if(port == NULL) {
			uoenc_err("No port number provided.");
		}
		
		int port_num = atoi(port);
		if(port_num < 0 || port_num > 65535) {
			uoenc_err("Invalid port number");
		}
		
		// Start listening
		struct addrinfo hints;
		struct addrinfo * addrinfo;
		bzero(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;
		int status = getaddrinfo(NULL, port, &hints, &addrinfo);
		if(status != 0) {
			fprintf(stderr, "%s\n", gai_strerror(status));
			uoenc_err("Could not resolve address.");
		}
		sock = socket(addrinfo->ai_family, addrinfo->ai_socktype,
			addrinfo->ai_protocol);
		if(sock == -1) {
			perror(progname);
			uoenc_err("Unable to open socket.");
		}
		status = bind(sock, addrinfo->ai_addr, addrinfo->ai_addrlen);
		if(status == -1) {
			close(sock);
			perror(progname);
			uoenc_err("Unable to bind socket.");
		}
		freeaddrinfo(addrinfo);
		status = listen(sock, 1);
		if(status == -1) {
			perror(progname);
			uoenc_err("Unable to listen on socket.");
		}
		
		// Accept incoming connections
		struct sockaddr_storage sockaddr;
		socklen_t sockaddr_len = sizeof(struct sockaddr_storage); 
		int insock = accept(sock, (struct sockaddr *)&sockaddr, &sockaddr_len);
		if(insock == -1) {
			perror(progname);
			uoenc_err("Unable to accept incoming connection.");
		}
		
		// Receive incoming data
		struct uoenc_network_packet * packet = uoenc_recv_packet(insock);
		if(packet == NULL) {
			uoenc_err("Unable to receive packet.");
		}
		
		// Parse incoming data
		outfile_name = malloc(FILENAME_LEN);
		bool parse_stat = uoenc_parse_packet(packet, msg, salt, hmac,
			outfile_name);
		if(!parse_stat) {
			uoenc_err("Unable to parse packet.");
		}
		
		printf("Incoming file: %s\n", packet->filename);
		
		free(packet);
		
		close(insock);
		close(sock);
		
	}
	
	// Validate output filename
	if(outfile_name == NULL || strnlen(outfile_name, FILENAME_LEN) == 0) {
		uoenc_err("Invalid output filename");
	}
		
	// Check if output file already exists.
	struct stat outfile_stat;
	int outfile_err = stat(outfile_name, &outfile_stat);
	if(!outfile_err) {
		uoenc_err("output file already exists");
	}
		
	// Read password
	char * password = getpass("Password: ");
	if(password == NULL || strnlen(password, PASS_MAX) == 0) {
		uoenc_err("Password cannot be blank.\n");
	}
	
	// Recreate key using password and salt from input
	struct uocrypt_key * key = uocrypt_make_key(password, 
		strlen(password), salt, UOCRYPT_SALT_LEN);
	
	// Calculate and verify HMAC
	unsigned char * hmac_in = uocrypt_hmac(msg->txt, msg->txtlen, key);
	int hmac_cmp = memcmp(hmac, hmac_in, uocrypt_hmac_len());
	if(hmac_cmp != 0) {
		uoenc_err("HMAC verification failed (probably incorrect password)");
	}
	
	// Open output file for writing.
	FILE * outfh = fopen(outfile_name, "wb");
	if(outfh == NULL) {
		perror(progname);
		exit(EXIT_FAILURE);
	}
	
	// Decrypt input
	unsigned char * decrypted_msg = uocrypt_decrypt(msg, key);
	size_t nb = fwrite(decrypted_msg, 1, msg->txtlen, outfh);
	if(nb != msg->txtlen) {
		uoenc_err("error writing decrypted output");
	}
	
	fclose(outfh);
	
	free(decrypted_msg);
	free(key);
	free(msg->txt);
	free(msg);
	free(hmac);
	free(hmac_in);
	free(salt);
	free(outfile_name);
	
	
	return EXIT_SUCCESS;
}
