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
	bool local = false;
	char * addr_str = NULL;
	char * addr = NULL;
	char * port = NULL;
	char * filename = NULL;
	int sock = -1;
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
		
	// Validate command line arguments
	if(local && addr_str) {
		uoenc_err("can't use both -l and -d simultaneously.");
	}
	
	if((!local && !addr_str) || !filename) {
		fprintf(stderr, "usage: %s filename [-d address] [-l]\n", progname);
		exit(EXIT_FAILURE);
	}
	
	// Validate network address
	if(addr_str) {
		const char * s = ":";
		addr = strtok(addr_str, s);
		port = strtok(NULL, s);
		if(port == NULL) {
			uoenc_err("No port number provided");
		}
		int port_num = atoi(port);
		if(port_num < 0 || port_num > 65535) {
			uoenc_err("Invalid port number provided");
		}
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
		
	if(local) {
		// Open output file
		FILE * outf = fopen(outfile_name, "wb");
		if(outf == NULL) {
			perror(progname);
			exit(EXIT_FAILURE);
		}
		bool status = uoenc_write_uo_file(outf, key, msg, hmac);
		if(!status) {
			uoenc_err("failed to write output file.");
		}
		fclose(outf);
	} else {
		struct addrinfo hints;
		struct addrinfo * addrinfo;
		bzero(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		int status = getaddrinfo(addr, port, &hints, &addrinfo);
		if(status != 0) {
			fprintf(stderr, "%s\n", gai_strerror(status));
			uoenc_err("Unable to resolve address");
		}
		
		sock = socket(addrinfo->ai_family, addrinfo->ai_socktype, 
			addrinfo->ai_protocol);
		if(sock == -1) {
			perror(progname);
			uoenc_err("Unable to open socket.");
		}
		status = connect(sock, addrinfo->ai_addr, addrinfo->ai_addrlen);
		if(status == -1) {
			close(sock);
			perror(progname);
			uoenc_err("Unable to connect socket.");
		}
		freeaddrinfo(addrinfo);
		
		struct uoenc_network_packet * packet = 
			uoenc_create_packet(key, msg, hmac, filename);
		bool send_stat = uoenc_send_packet(sock, packet);
		
		if(!send_stat) {
			uoenc_err("Failed to send packet.");
		}
		
		free(packet);
		close(sock);
	}
	
	
	free(hmac);
	free(key);
	free(msg->txt);
	free(msg);
	
	
	munmap(input_buf, infile_stat.st_size);
	close(infd);
	
	return EXIT_SUCCESS;
}
