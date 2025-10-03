#ifndef CITADEL_CRYPTO_H
#define CITADEL_CRYPTO_H

#include <stddef.h>


#define SALT_LEN 16
#define IV_LEN 12
#define TAG_LEN 16

// A structure to hold all parts of the encrypted payload
typedef struct {
    unsigned char* ciphertext;
    size_t ciphertext_len;
    unsigned char salt[SALT_LEN];
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
} CryptoPayload;

/**
 * Encrypts plaintext data using AES-256-GCM with a key derived from a password.
 * @param plaintext The data to encrypt.
 * @param plaintext_len The length of the data.
 * @param password The master password.
 * @return A pointer to a CryptoPayload struct containing all encrypted data. The caller must free this with crypto_payload_free(). Returns NULL on failure.
 */
CryptoPayload* citadel_encrypt(const unsigned char* plaintext, size_t plaintext_len, const char* password);

/**
 * Decrypts a CryptoPayload using AES-256-GCM.
 * @param payload The encrypted data payload.
 * @param password The master password.
 * @param decrypted_len A pointer to store the length of the decrypted data.
 * @return A pointer to the decrypted plaintext. The caller must free this memory. Returns NULL if decryption fails (wrong password or tampered data).
 */
unsigned char* citadel_decrypt(const CryptoPayload* payload, const char* password, size_t* decrypted_len);

/**
 * Frees all memory associated with a CryptoPayload struct.
 * @param payload The payload to free.
 */
void crypto_payload_free(CryptoPayload* payload);

#endif //CITADEL_CRYPTO_H