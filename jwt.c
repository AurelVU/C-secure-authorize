//
// Created by Владимир Ушаков on 11.03.2023.
//

#include "jwt.h"
#include "hash_list.h"

char* jwt_encode(unsigned const char* const payload,
                 unsigned const char* const key,
                 unsigned const char* const encode_func_name
) {
    unsigned char* prefix = malloc(sizeof(unsigned char) * BUFFER_SIZE);
    snprintf((char*)prefix,sizeof(unsigned char) * BUFFER_SIZE, "{\"alg\":\"%s\",\"typ\":\"JWT\"}", encode_func_name);
    unsigned char* data = malloc(sizeof(unsigned char) * BUFFER_SIZE);
    snprintf((char*) data,
             sizeof(unsigned char) * BUFFER_SIZE,
             "%s.%s",
             base64url_encode(
                     prefix,
                     strlen((char*)prefix)
             ),
             base64url_encode(
                     payload,
                     strlen((char*)payload)
             )
    );
    unsigned char* mac = malloc(sizeof(char) * BUFFER_SIZE);
    unsigned int mac_size;
    get_hash_function((char*)encode_func_name)(
            (char*)key,
            (int)strlen((char*)key),
            (unsigned char*)data,
            strlen((char*)data),
            mac,
            (unsigned int *) &mac_size
    );
    char* jwt = malloc(sizeof(unsigned char) * BUFFER_SIZE);
    snprintf(jwt, sizeof(unsigned char) * BUFFER_SIZE, "%s.%s", data, base64url_encode(mac, mac_size));

    free(prefix);
    free(data);
    free(mac);

    return jwt;
}

int jwt_validate(
        unsigned const char* const token,
        unsigned const char* const secret_key,
        unsigned const char* const encode_func_name
) {
    int compare_result = TOKEN_IS_NOT_VALID;

    char* token_copy = malloc(sizeof(char) * (strlen((char*)token) + 1));
    strcpy(token_copy, (char*)token);

    char* token_parts[3];

    token_parts[0] = strtok(token_copy, ".");
    token_parts[1] = strtok(NULL, ".");
    token_parts[2] = strtok(NULL, ".");

    char* payload = base64url_decode(token_parts[1]);

    char* data = malloc(sizeof(char) * (strlen(token_parts[0]) + strlen(token_parts[1]) + 2));
    snprintf(data, strlen(token_parts[0]) + strlen(token_parts[1]) + 2, "%s.%s", token_parts[0], token_parts[1]);

    unsigned char* mac = malloc(sizeof(char) * BUFFER_SIZE);
    unsigned int mac_size;
    get_hash_function((char*)encode_func_name)
            (
                    (char*)secret_key,
                    (int)strlen((char*)secret_key),
                    (unsigned char*)data,
                    strlen(data),
                    mac,
                    (unsigned int *) &mac_size
            );
    char* base64hash = base64url_encode(mac, (int)mac_size);

    cJSON* json = cJSON_Parse(payload);

    if (!strcmp(base64hash, token_parts[2])) {
        cJSON* expCJSON = cJSON_GetObjectItemCaseSensitive(json, "exp");
        if (expCJSON == NULL || !cJSON_IsNumber(expCJSON)) {
            goto exit;
        }
        if (expCJSON->valueint < time(NULL)) {
            compare_result = TOKEN_EXPIRED;
            goto exit;
        }

        compare_result = TOKEN_IS_VALID;
    }

    exit:
    cJSON_Delete(json);
    free(payload);
    free(data);
    free(token_copy);
    free(mac);
    free(base64hash);

    return compare_result;
}
