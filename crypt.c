#include "crypt.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>

void initialize_libgcrypt(void) {
    // From libgcrypt manual, section 2.4, "Initializing the library"
    if(!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "Error: libgcrypt header and library versions do not match.\n");
        exit(EXIT_FAILURE);
    }

    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}
