#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "uoutil.h"

char * progname;

void uoenc_err(const char * err) {
	fprintf(stderr, "%s: %s\n", progname, err);
	exit(EXIT_FAILURE);
}

struct uoenc_file_header * uoenc_make_header(void) {
	struct uoenc_file_header * header = 
		malloc(sizeof(struct uoenc_file_header));
	strncpy(header->identifier, IDENTIFIER, sizeof(header->identifier));
	return header;
}

char * uoenc_outfile_name(char * filename) {
	char extension[] = EXTENSION;
	size_t infile_name_len = strnlen(filename, 
		NAME_MAX - sizeof(extension));
	size_t outfile_name_len = infile_name_len + sizeof(extension);
	char * outfile_name = malloc(outfile_name_len);
	snprintf(outfile_name, outfile_name_len, "%*s%s", (int) infile_name_len,
		filename, extension);
	return outfile_name;
}

