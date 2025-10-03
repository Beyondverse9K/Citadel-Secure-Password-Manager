#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


void crypto_payload_free(CryptoPayload* payload) {
    if (payload) {
        // Securely zero out the ciphertext before freeing
        if (payload->ciphertext) {
            memset(payload->ciphertext, 0, payload->ciphertext_len);
        }
        free(payload->ciphertext);
        free(payload);
    }
}


static int derive_key_pbkdf2(const char* password, const unsigned char* salt, unsigned char* key, size_t key_len) {
    int iterations = 310000;
    int result = PKCS5_PBKDF2_HMAC(
        password,
        (int)strlen(password),
        salt,
        SALT_LEN,
        iterations,
        EVP_sha256(),
        (int)key_len,
        key
    );

    return result == 1; // Returns 1 on success
}

CryptoPayload* citadel_encrypt(const unsigned char* plaintext, size_t plaintext_len, const char* password) {
    CryptoPayload* payload = malloc(sizeof(CryptoPayload));
    if (!payload) return NULL;
    payload->ciphertext = malloc(plaintext_len);
    if (!payload->ciphertext) {
        free(payload);
        return NULL;
    }
    if (RAND_bytes(payload->salt, SALT_LEN) != 1 || RAND_bytes(payload->iv, IV_LEN) != 1) {
        crypto_payload_free(payload);
        return NULL;
    }

    unsigned char key[32]; // AES-256 uses a 32-byte key
    if (!derive_key_pbkdf2(password, payload->salt, key, sizeof(key))) {
        crypto_payload_free(payload);
        return NULL;
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, payload->iv);
    EVP_EncryptUpdate(ctx, payload->ciphertext, &len, plaintext, (int)plaintext_len);
    payload->ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, payload->ciphertext + len, &len);
    payload->ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, payload->tag);
    EVP_CIPHER_CTX_free(ctx);
    // Securely zero out the derived key from memory
    memset(key, 0, sizeof(key));
    return payload;
}

unsigned char* citadel_decrypt(const CryptoPayload* payload, const char* password, size_t* decrypted_len) {
    unsigned char key[32];
    if (!derive_key_pbkdf2(password, payload->salt, key, sizeof(key))) {
        return NULL;
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char* plaintext = malloc(payload->ciphertext_len);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        // Securely zero out the key before returning
        memset(key, 0, sizeof(key));
        return NULL;
    }
    int len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, payload->iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, payload->ciphertext, (int)payload->ciphertext_len);
    *decrypted_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)payload->tag);
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        // Securely zero out the key before returning
        memset(key, 0, sizeof(key));
        return NULL; // Authentication failed!
    }
    *decrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);
    // Securely zero out the key from memory after successful use
    memset(key, 0, sizeof(key));
    return plaintext;
}