#include <stdio.h>
#include <openssl/crypto.h>

/* A harmless version query keeps libcrypto in the ELF DT_NEEDED entries.
 * This fixture tests package detection, not exploitation of the CVE. */
int main(void)
{
    puts(OpenSSL_version(OPENSSL_VERSION));
    return 0;
}
