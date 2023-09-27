#include <assert.h>
#include "stdio.h"
#include "cJSON.h"
#include "jwt.h"
#include "hash_list.h"

char *create_payload(
        int id,
        char* role,
        // nullable
        unsigned const char* const iss, // Codex Team
        unsigned const char* const sub, // auth
        const time_t* const exp, // 1505467756869,
        const time_t* const iat // 150546715206
    ) {
    assert(role != NULL);

    char* string = NULL;
    cJSON *payload = cJSON_CreateObject();
    if (payload == NULL)
    {
        goto end;
    }

    cJSON* idCJSON = cJSON_CreateNumber(id);
    if (idCJSON == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(payload, "id", idCJSON);

    cJSON* roleCJSON = cJSON_CreateString(role);
    if (role == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(payload, "role", roleCJSON);

    if (iss != NULL) {
        cJSON *issCJSON = cJSON_CreateString(iss);
        if (issCJSON == NULL) {
            goto end;
        }
        cJSON_AddItemToObject(payload, "iss", issCJSON);
    }

    if (sub != NULL) {
        cJSON *subCJSON = cJSON_CreateString(sub);
        if (subCJSON == NULL) {
            goto end;
        }
        cJSON_AddItemToObject(payload, "sub", subCJSON);
    }


    if (iat != NULL) {
        cJSON *iatCJSON = cJSON_CreateNumber(*iat);
        if (iatCJSON == NULL) {
            goto end;
        }
        cJSON_AddItemToObject(payload, "iat", iatCJSON);
    }

    if (exp != NULL) {
        cJSON *expCJSON = cJSON_CreateNumber(*exp);
        if (expCJSON == NULL) {
            goto end;
        }
        cJSON_AddItemToObject(payload, "exp", expCJSON);
    }

    string = cJSON_PrintUnformatted(payload);
    if (string == NULL)
    {
        fprintf(stderr, "Failed to print payload.\n");
    }

    end:
    cJSON_Delete(payload);
    return string;
}

int main() {
    int lifetime = 10000000000;

    time_t t = time(NULL);
    time_t t2 = t + lifetime;
    unsigned char* encoded_json = (unsigned char*) create_payload(
            1,
            "admin",
            NULL,
            NULL,
            &t2,
            &t
        );
    unsigned char* secret_key = (unsigned char*) "GeeksForGeeks";
    unsigned char* encoded_func_name = HASH_NAME(HS256);

    unsigned char* token = (unsigned char*) jwt_encode(
        encoded_json,
        secret_key,
        encoded_func_name
    );

    printf("%s\n", token);
    switch (jwt_validate(
            token,
            secret_key,
            encoded_func_name)
            ) {
        case TOKEN_IS_VALID:
            printf("Token is valid\n");
            break;
        case TOKEN_IS_NOT_VALID:
            printf("Token is not valid\n");
            break;
        case TOKEN_EXPIRED:
            printf("Token expired\n");
            break;
    }
    return 0;
}
