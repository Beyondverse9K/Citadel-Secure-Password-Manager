cmake_minimum_required(VERSION 3.10)

project(Citadel C)

set(CMAKE_C_STANDARD 11)

find_package(OpenSSL REQUIRED)

add_executable(Citadel
        src/main.c
        src/crypto.c
        src/vault.c
        src/security.c
        src/clipboard.c
        src/ui.c
)

target_link_libraries(Citadel PRIVATE OpenSSL::Crypto OpenSSL::SSL)