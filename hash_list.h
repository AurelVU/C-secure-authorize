//
// Created by Владимир Ушаков on 26.02.2023.
//

#ifndef SECURE_AUTHORIZE_HASH_LIST_H
#define SECURE_AUTHORIZE_HASH_LIST_H
#include <openssl/hmac.h>

#define HASH_NAME(s) #s
#define HASH_FUNCTION_NAME(NAME) HMAC_ ##NAME
#define HASH_BY_NAME(NAME) void HASH_FUNCTION_NAME(NAME)(const char *key, int key_len, \
const unsigned char *data, size_t data_len, \
unsigned char *md, unsigned int *md_len) { \
    HMAC(EVP_ ##NAME(), key, key_len, data, data_len, md, md_len); \
}

#define HS256 sha256
HASH_BY_NAME(sha256)

#define HS512 sha512
HASH_BY_NAME(sha512)

void (*get_hash_function(const char* const name))(
        const char *key, int key_len,
        const unsigned char *data, size_t data_len,
        unsigned char *md, unsigned int *md_len) {
    if (!strcmp(name, HASH_NAME(HS256))) return HASH_FUNCTION_NAME(sha256);
    if (!strcmp(name, HASH_NAME(HS512))) return HASH_FUNCTION_NAME(sha512);
    return NULL;
}

#endif //SECURE_AUTHORIZE_HASH_LIST_H
