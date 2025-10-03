#include "vault.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#define INITIAL_CAPACITY 10
#define ENTRY_SEPARATOR "---CITADEL_ENTRY_SEPARATOR---\n"

Vault* vault_new() {
    Vault* vault = malloc(sizeof(Vault));
    if (!vault) return NULL;
    vault->credentials = malloc(INITIAL_CAPACITY * sizeof(Credential));
    if (!vault->credentials) {
        free(vault);
        return NULL;
    }
    vault->count = 0;
    vault->capacity = INITIAL_CAPACITY;
    return vault;
}

void vault_free(Vault* vault) {
    if (!vault) return;
    for (size_t i = 0; i < vault->count; ++i) {
        free(vault->credentials[i].service);
        free(vault->credentials[i].username);
        free(vault->credentials[i].password);
    }
    free(vault->credentials);
    free(vault);
}

// Simple helper to duplicate a string
char* strdup_safe(const char* s) {
    char* d = malloc(strlen(s) + 1);
    if (d) strcpy(d, s);
    return d;
}

void vault_add_credential(Vault* vault, const char* service, const char* username, const char* password) {
    if (vault->count >= vault->capacity) {
        size_t new_capacity = vault->capacity * 2;
        Credential* new_creds = realloc(vault->credentials, new_capacity * sizeof(Credential));
        if (!new_creds) {
            fprintf(stderr, "Error: Failed to reallocate memory for credentials.\n");
            return;
        }
        vault->credentials = new_creds;
        vault->capacity = new_capacity;
    }

    vault->credentials[vault->count].service = strdup_safe(service);
    vault->credentials[vault->count].username = strdup_safe(username);
    vault->credentials[vault->count].password = strdup_safe(password);
    vault->count++;
}

static void parse_plaintext_into_vault(Vault* vault, const unsigned char* plaintext, size_t len) {
    char* data = strdup_safe((const char*)plaintext); // Work on a mutable copy
    data[len] = '\0'; // Ensure null termination

    char* line = strtok(data, "\n");
    while(line) {
        char* service = line;
        char* username = strtok(NULL, "\n");
        char* password = strtok(NULL, "\n");
        char* separator = strtok(NULL, "\n");

        if (!username || !password || !separator || strcmp(separator, "---CITADEL_ENTRY_SEPARATOR---") != 0) {
            fprintf(stderr, "Warning: Vault data may be corrupt. Halting parse.\n");
            break;
        }
        vault_add_credential(vault, service, username, password);
        line = strtok(NULL, "\n");
    }
    free(data);
}

Vault* vault_load(const char* password) {
    FILE* f = fopen(VAULT_FILE, "rb");
    if (!f) return vault_new(); // File doesn't exist, create a new vault

    CryptoPayload payload;
    fread(payload.salt, 1, SALT_LEN, f);
    fread(payload.iv, 1, IV_LEN, f);
    fread(payload.tag, 1, TAG_LEN, f);

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    payload.ciphertext_len = file_size - (SALT_LEN + IV_LEN + TAG_LEN);
    payload.ciphertext = malloc(payload.ciphertext_len);
    fseek(f, SALT_LEN + IV_LEN + TAG_LEN, SEEK_SET);
    fread(payload.ciphertext, 1, payload.ciphertext_len, f);
    fclose(f);

    size_t decrypted_len;
    unsigned char* plaintext = citadel_decrypt(&payload, password, &decrypted_len);
    free(payload.ciphertext); // We are done with the ciphertext buffer

    if (!plaintext) {
        fprintf(stderr, "Error: Decryption failed. Incorrect password or vault is corrupt.\n");
        return NULL;
    }

    Vault* vault = vault_new();
    parse_plaintext_into_vault(vault, plaintext, decrypted_len);

    free(plaintext);
    return vault;
}

int vault_save(const Vault* vault, const char* password) {
    size_t total_len = 1; // Start with 1 for null terminator
    for (size_t i = 0; i < vault->count; ++i) {
        total_len += strlen(vault->credentials[i].service) + 1;
        total_len += strlen(vault->credentials[i].username) + 1;
        total_len += strlen(vault->credentials[i].password) + 1;
        total_len += strlen(ENTRY_SEPARATOR) + 1;
    }

    char* plaintext = malloc(total_len);
    plaintext[0] = '\0';
    for (size_t i = 0; i < vault->count; ++i) {
        strcat(plaintext, vault->credentials[i].service); strcat(plaintext, "\n");
        strcat(plaintext, vault->credentials[i].username); strcat(plaintext, "\n");
        strcat(plaintext, vault->credentials[i].password); strcat(plaintext, "\n");
        strcat(plaintext, ENTRY_SEPARATOR);
    }

    CryptoPayload* payload = citadel_encrypt((unsigned char*)plaintext, strlen(plaintext), password);
    free(plaintext);

    if (!payload) {
        fprintf(stderr, "Error: Encryption failed during save.\n");
        return -1;
    }

    FILE* f = fopen(VAULT_FILE, "wb");
    if (!f) {
        crypto_payload_free(payload);
        fprintf(stderr, "Error: Could not open vault file for writing.\n");
        return -1;
    }

    fwrite(payload->salt, 1, SALT_LEN, f);
    fwrite(payload->iv, 1, IV_LEN, f);
    fwrite(payload->tag, 1, TAG_LEN, f);
    fwrite(payload->ciphertext, 1, payload->ciphertext_len, f);

    fclose(f);
    crypto_payload_free(payload);
    return 0;
}


Credential* vault_find_credential(const Vault* vault, const char* service) {
    for (size_t i = 0; i < vault->count; ++i) {
        if (strcasecmp(vault->credentials[i].service, service) == 0) {
            return &vault->credentials[i];
        }
    }
    return NULL;
}

void vault_delete_credential(Vault* vault, const char* service) {
    int found_index = -1;
    for (size_t i = 0; i < vault->count; ++i) {
        if (strcasecmp(vault->credentials[i].service, service) == 0) {
            found_index = (int)i;
            break;
        }
    }

    if (found_index != -1) {
        // Free the memory of the credential being deleted
        free(vault->credentials[found_index].service);
        free(vault->credentials[found_index].username);
        free(vault->credentials[found_index].password);

        // Shift all subsequent elements one position to the left
        for (size_t i = found_index; i < vault->count - 1; ++i) {
            vault->credentials[i] = vault->credentials[i + 1];
        }
        vault->count--;
        printf("Credential for '%s' deleted.\n", service);
    } else {
        printf("Credential for '%s' not found.\n", service);
    }
}