cmake_minimum_required(VERSION 3.24)
include(FetchContent)
project(secure_authorize)

set(C_STANDARD C99)

FetchContent_Declare(
        cJSON
        GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
)
FetchContent_MakeAvailable(cjson)

add_library(jwt jwt.c)
add_executable(${PROJECT_NAME} main.c)

add_dependencies(${PROJECT_NAME} cjson)

include_directories(${cjson_SOURCE_DIR})
find_package(OpenSSL REQUIRED)

target_link_libraries(jwt cjson OpenSSL::Crypto)
target_link_libraries(${PROJECT_NAME} cjson jwt)
