#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "fscrypt.hpp"

int main(int argc, const char * argv[]) {
    char s[] = "hello world";
    char *outbuf, *recvbuf;
    char pass[] = "top secret";
    int len = 0;
    int recvlen = 0;

    outbuf = (char *) fs_encrypt((void *) s, strlen(s)+1, pass, &len);
    printf("%s %d\n", "length after encryption = ", len);

    int i = 0;
    printf("ciphertext = ");
    for (i = 0; i < len; i++)
        printf("%02x", outbuf[i]);
    printf("\n");
    
    recvbuf  = (char *) fs_decrypt((void *) outbuf, len, pass, &recvlen);
    std::cout << recvlen << "\n";
    assert(memcmp(s, recvbuf, recvlen) == 0);
    assert(recvlen == (strlen(s) + 1));
    printf("plaintext = %s\n", recvbuf);
}
