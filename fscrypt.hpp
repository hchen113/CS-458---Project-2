#ifndef fscrypt_hpp
#define fscrypt_hpp

#include <stdio.h>
#include <iostream>
#include "openssl/blowfish.h"
// encrypt plaintext of length bufsize. Use keystr as the key.
const int BLOCKSIZE = 8;           // Block size for blowfish

void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen);

// decrypt ciphertext of length bufsize. Use keystr as the key.
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen);

#endif /* fscrypt_hpp */
