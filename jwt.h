//
// Created by Владимир Ушаков on 22.02.2023.
//

#ifndef SECURE_AUTHORIZE_JWT_H
#define SECURE_AUTHORIZE_JWT_H

#include "string.h"
#include "base64.h"
#include "cJSON.h"

#define BUFFER_SIZE 50000

#define TOKEN_IS_VALID 0
#define TOKEN_IS_NOT_VALID 1
#define TOKEN_EXPIRED 2

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#define EXPORT __attribute__((visibility("default")))
#else
#define EXPORT
#endif

EXPORT char* jwt_encode(
        unsigned const char* payload,
        unsigned const char* key,
        unsigned const char* encode_func_name
);

EXPORT int jwt_validate(
        unsigned const char* token,
        unsigned const char* secret_key,
        unsigned const char* encode_func_name
);


#endif //SECURE_AUTHORIZE_JWT_H
