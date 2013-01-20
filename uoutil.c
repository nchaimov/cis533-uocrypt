#include <stdlib.h>
#include <stdio.h>
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
