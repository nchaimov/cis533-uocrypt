#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "uoio.h"

char * progname = NULL;

// Print an error and exit
void uoenc_err(const char * err) {
	if(progname != NULL) {
		fprintf(stderr, "%s: %s\n", progname, err);
	}
	exit(EXIT_FAILURE);
}

// Allocate memory for a file header and fill in the identifier field
struct uoenc_file_header * uoenc_make_header(void) {
	struct uoenc_file_header * header = 
		malloc(sizeof(struct uoenc_file_header));
	strncpy(header->identifier, IDENTIFIER, sizeof(header->identifier));
	return header;
}

// Determine the output file name for a given input file name
char * uoenc_outfile_name(char * filename) {
	if(filename == NULL) {
		fprintf(stderr, "Error: uoenc_outfile_name 'filename' was NULL\n");
		return NULL;
	}
	char extension[] = EXTENSION;
	size_t infile_name_len = strnlen(filename, 
		NAME_MAX - sizeof(extension));
	size_t outfile_name_len = infile_name_len + sizeof(extension);
	char * outfile_name = malloc(outfile_name_len);
	snprintf(outfile_name, outfile_name_len, "%*s%s", (int) infile_name_len,
		filename, extension);
	return outfile_name;
}

// Read a .uo file and fill in the appropriate structures
// The caller will still need to calculate the key and set it in the
// uocrypt_key before using it.
bool uoenc_read_uo_file(FILE * fh, struct uocrypt_enc_msg * msg, unsigned char * salt, unsigned char * hmac) {
	
	if(salt == NULL) {
		uoenc_err("read_uo_file 'salt' was NULL");
	}
	
	if(msg == NULL) {
		uoenc_err("read_uo_file 'msg' was NULL");
	}
	
	if(hmac == NULL) {
		uoenc_err("read_uo_file 'hmac' was NULL");
	}
	
	struct uoenc_file_header * header =
		malloc(sizeof(struct uoenc_file_header));
	
	// Read file header 
	size_t nb = fread(header, sizeof(struct uoenc_file_header), 1, fh);
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
	nb = fread(hmac, 1, header->hmac_len, fh);
	if(nb != header->hmac_len) {
		uoenc_err("Invalid HMAC length header field");
	}
		
	// Read encrypted message from file
	msg->txt = malloc(header->txt_len);
	nb = fread(msg->txt, 1, header->txt_len, fh);
	if(nb != header->txt_len) {
		uoenc_err("Invalid text length header field");
	}
	msg->txtlen = header->txt_len;
			
	// Set IV
	memcpy(msg->iv, header->iv, UOCRYPT_BLOCK_LEN);
		
	// Set salt
	memcpy(salt, header->salt, UOCRYPT_SALT_LEN);
		
	free(header);
		
	return true;
}

// Write .uo file
bool uoenc_write_uo_file(FILE * fh, struct uocrypt_key * key, struct uocrypt_enc_msg * msg, unsigned char * hmac) {
	if(key == NULL) {
		uoenc_err("write_uo_file 'key' was NULL");
	}
	
	if(msg == NULL) {
		uoenc_err("write_uo_file 'msg' was NULL");
	}
	
	if(hmac == NULL) {
		uoenc_err("write_uo_file 'hmac' was NULL");
	}
	
	struct uoenc_file_header * header = uoenc_make_header();
	memcpy(header->salt, key->salt, UOCRYPT_SALT_LEN);
	memcpy(header->iv, msg->iv, UOCRYPT_BLOCK_LEN);
	header->hmac_len = uocrypt_hmac_len();
	header->txt_len = msg->txtlen;
	
	size_t nm;
	
	// Write header
	nm = fwrite(header, 1, sizeof(struct uoenc_file_header), fh);
	if(nm < 1) {
		perror(progname);
		return false;
	}
	// Write HMAC
	nm = fwrite(hmac, 1, header->hmac_len, fh);
	if(nm < 1) {
		perror(progname);
		return false;
	}
	// Write encrypted text
	nm = fwrite(msg->txt, 1, header->txt_len, fh);
	if(nm < 1) {
		perror(progname);
		return false;
	}
	
	free(header);
	return true;
}

// Allocate memory for a packet and fill out the structs
struct uoenc_network_packet * uoenc_create_packet(struct uocrypt_key * key, struct uocrypt_enc_msg * msg, unsigned char * hmac, char * filename) {
	
	if(key == NULL) {
		uoenc_err("create_packet 'key' was NULL");
	}
	
	if(msg == NULL) {
		uoenc_err("create_packet 'msg' was NULL");
	}
	
	if(hmac == NULL) {
		uoenc_err("create_packet 'hmac' was NULL");
	}
	
	if(filename == NULL) {
		uoenc_err("create_packet 'filename' was NULL");
	}
	
	
	
	struct uoenc_network_packet * packet = 
		malloc(sizeof(struct uoenc_network_packet));
	
	// Fill in packet and file headers
	packet->packet_len = htonl(sizeof(struct uoenc_network_packet) 
		+ uocrypt_hmac_len() + msg->txtlen);
	strncpy(packet->filename, filename, FILENAME_LEN);
	strncpy(packet->header.identifier, IDENTIFIER,
		sizeof(packet->header.identifier));
	memcpy(packet->header.salt, key->salt, UOCRYPT_SALT_LEN);
	memcpy(packet->header.iv, msg->iv, UOCRYPT_BLOCK_LEN);
	packet->header.hmac_len = htonl(uocrypt_hmac_len());
	packet->header.txt_len = htonl(msg->txtlen);
	
	// Fill in packet body
	memcpy(packet->body, hmac, uocrypt_hmac_len());
	memcpy(&(packet->body[uocrypt_hmac_len()]), msg->txt, msg->txtlen);
	
	return packet;
}

// Write packet to socket
bool uoenc_send_packet(int socket, struct uoenc_network_packet * packet) {
	if(packet == NULL) {
		uoenc_err("send_packet 'packet' was NULL");
	}
	
	
	uint32_t total_sent = 0;
	uint32_t len = packet->packet_len;
	ssize_t s;
	
	while(total_sent < len) {
		s = send(socket, &(packet[total_sent]), len - total_sent, 0);
		if(s == -1) {
			break; // An error occurred.
		}
		total_sent += s;
	}
	
	if(s == -1) {
		perror(progname);
		return false;
	}
	
	return true;
}

// Read packet from socket
struct uoenc_network_packet * uoenc_recv_packet(int socket) {
	uint32_t total_recv = 0;
	uint32_t len;
	ssize_t s;
	
	s = recv(socket, &len, sizeof(uint32_t), 0);
	if(s == -1) {
		perror(progname);
		return NULL;
	}
	
	len = ntohl(len);
	if(len < sizeof(struct uoenc_network_packet)) {
		uoenc_err("Packet length too short.");
	}
	
	struct uoenc_network_packet * packet = malloc(len);
	total_recv += s;
	packet->packet_len = len;
	
	while(total_recv < len) {
		s = recv(socket, &(packet[total_recv]), len - total_recv, 0);
		if(s == -1) {
			break; // An error occurred.
		}
		total_recv += s;
	}
	
	if(s == -1) {
		perror(progname);
		free(packet);
		return NULL;
	}
	
	return packet;
		
}

bool uoenc_parse_packet(struct uoenc_network_packet * packet, struct uocrypt_enc_msg * msg, unsigned char * salt, unsigned char * hmac, char * filename) {
	if(packet == NULL) {
		uoenc_err("parse_packet 'packet' was NULL");
	}
	if(msg == NULL) {
		uoenc_err("parse_packet 'msg' was NULL");
	}
	if(salt == NULL) {
		uoenc_err("parse_packet 'salt' was NULL");
	}
	if(hmac == NULL) {
		uoenc_err("parse_packet 'hmac' was NULL");
	}
	if(filename == NULL) {
		uoenc_err("parse_packet 'filename' was NULL");
	}
	
	// Check header identifier
	char identifier[] = IDENTIFIER;
	int identcmp = memcmp(packet->header.identifier, identifier,
		sizeof(identifier) - 1);
	if(identcmp != 0) {
		uoenc_err("Invalid packet header");
	}
	
	strncpy(filename, packet->filename, FILENAME_LEN);
	memcpy(salt, packet->header.salt, UOCRYPT_SALT_LEN);
	memcpy(msg->iv, packet->header.iv, UOCRYPT_BLOCK_LEN);
	memcpy(hmac, packet->body, ntohl(packet->header.hmac_len));
	msg->txtlen = ntohl(packet->header.txt_len);
	memcpy(msg->txt, &(packet->body[ntohl(packet->header.hmac_len)]),
		msg->txtlen);
	
	return true;
}

