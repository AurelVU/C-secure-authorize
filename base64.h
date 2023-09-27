//
// Created by Владимир Ушаков on 21.02.2023.
//

#ifndef SECURE_AUTHORIZE_BASE64_H
#define SECURE_AUTHORIZE_BASE64_H

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdlib.h>

char* base64url_encode(const unsigned char *input, int length) {
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr = NULL;
    char *buff = NULL;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    int length2 = bptr->length;
    buff[bptr->length] = '\0';

    BIO_free_all(b64);

    // Convert '+' to '-' and '/' to '_' as per RFC 4648.
    for (int i = 0; i < length2; i++) {
        if (buff[i] == '+') {
            buff[i] = '-';
        } else if (buff[i] == '/') {
            buff[i] = '_';
        } else if (buff[i] == '=') {
            buff[i] = '\0';
        }
    }

    return buff;
}

char* base64url_decode(char* b64message) {
    BIO *b64 = NULL;
    BIO *bmem = NULL;
    char *buffer = NULL;

    buffer = (char *)malloc(strlen(b64message) + 1);
    memset(buffer, 0, strlen(b64message) + 1);

    // Convert '-' to '+' and '_' to '/' as per RFC 4648.
    for (int i = 0; i < strlen(b64message); i++) {
        if (b64message[i] == '-') {
            b64message[i] = '+';
        } else if (b64message[i] == '_') {
            b64message[i] = '/';
        }
    }

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(b64message, strlen(b64message));
    BIO_push(b64, bmem);
    BIO_read(b64, buffer, strlen(b64message));

    BIO_free_all(b64);

    return buffer;
}

#endif //SECURE_AUTHORIZE_BASE64_H
