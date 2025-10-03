#include "security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <fcntl.h>


const char* EXPECTED_BINARY_HASH = "MY_BINARY_HASH";

static void check_debugger() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        printf("Debugger detected. Exiting.\n");
        exit(EXIT_FAILURE);
    }
}

static void check_integrity() {

    if (strcmp(EXPECTED_BINARY_HASH, "MY_BINARY_HASH") == 0) {
        printf("WARNING: Binary hash is not set. Please recompile with a valid hash.\n");
        return; // Allow the program to continue in "developer" mode.
    }

    char self_path[1024];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len == -1) return;
    self_path[len] = '\0';

    int fd = open(self_path, O_RDONLY);
    if (fd < 0) return;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestInit_ex(mdctx, md, NULL);

    unsigned char buffer[8192];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }
    close(fd);
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    char current_hash_str[EVP_MAX_MD_SIZE * 2 + 1];
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(current_hash_str + (i * 2), "%02x", hash[i]);
    }

    if (strcmp(current_hash_str, EXPECTED_BINARY_HASH) != 0) {
        printf("Binary integrity failed or has been tampered with. Exiting.\n");
        exit(EXIT_FAILURE);
    }
}

void security_perform_checks() {
    check_debugger();
    check_integrity();
}