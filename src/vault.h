#ifndef CITADEL_VAULT_H
#define CITADEL_VAULT_H

#include <stddef.h>

#define VAULT_FILE "vault.db"

typedef struct {
    char* service;
    char* username;
    char* password;
} Credential;

typedef struct {
    Credential* credentials;
    size_t count;
    size_t capacity;
} Vault;

// Creates a new, empty vault.
Vault* vault_new();

// Frees all memory associated with a vault.
void vault_free(Vault* vault);

// Loads and decrypts the vault from disk.
Vault* vault_load(const char* password);

// Encrypts and saves the vault to disk. Returns 0 on success, -1 on failure.
int vault_save(const Vault* vault, const char* password);

// Adds a new credential to the vault.
void vault_add_credential(Vault* vault, const char* service, const char* username, const char* password);

// Finds a credential by service name (case-insensitive search).
Credential* vault_find_credential(const Vault* vault, const char* service);

// Deletes a credential from the vault by service name.
void vault_delete_credential(Vault* vault, const char* service);

#endif //CITADEL_VAULT_H