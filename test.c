#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include "crypt.h"

int main(int argc, char * argv[]) {
    initialize_libgcrypt();
    printf("libgcrypt initialization successful\n");

    return EXIT_SUCCESS;
}
