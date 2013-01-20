#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>

int main(int argc, char * argv[]) {
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
	
	if(filename != NULL) {
		printf("%s\n", filename);
	}
	
	return EXIT_SUCCESS;
}
