/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIP_BIO_H
#define KMIP_BIO_H

#include <openssl/ssl.h>
#include "kmip.h"

typedef struct query_response QueryResponse;
typedef struct locate_response LocateResponse;

typedef struct last_result
{
    enum operation operation;
    enum result_status result_status;
    enum result_reason result_reason;
    char result_message[128];
} LastResult;

int kmip_set_last_result(ResponseBatchItem*);
const LastResult* kmip_get_last_result(void);
int kmip_last_reason(void);
const char* kmip_last_message(void);
void kmip_clear_last_result(void);


/*
OpenSSH BIO API
*/

int kmip_bio_create_symmetric_key(BIO *, TemplateAttribute *, char **, int *);
int kmip_bio_get_symmetric_key(BIO *, char *, int, char **, int *);
int kmip_bio_destroy_symmetric_key(BIO *, char *, int);

int kmip_bio_create_symmetric_key_with_context(KMIP *, BIO *, TemplateAttribute *, char **, int *);
int kmip_bio_get_symmetric_key_with_context(KMIP *, BIO *, char *, int, char **, int *);
int kmip_bio_destroy_symmetric_key_with_context(KMIP *, BIO *, char *, int);

int kmip_bio_query_with_context(KMIP *ctx, BIO *bio, enum query_function queries[], size_t query_count, QueryResponse* query_result);
int kmip_bio_send_request_encoding(KMIP *, BIO *, char *, int, char **, int *);

/*
 * Mid-Level API Functions for Encrypt/Decrypt Operations
 * These functions require the caller to create and manage the KMIP context
 */

int kmip_bio_activate_with_context(KMIP *ctx, BIO *bio, char* key_uuid);

/**
 * Encrypt data using a KMIP server with caller-managed context
 *
 * @param ctx Initialized KMIP context
 * @param bio BIO connection to KMIP server
 * @param key_uuid Unique identifier of the encryption key
 * @param key_uuid_size Length of key_id string
 * @param plaintext Data to encrypt
 * @param plaintext_size Length of plaintext data
 * @param params Cryptographic parameters (can be NULL for server defaults)
 * @param ciphertext Output: encrypted data (caller must free)
 * @param ciphertext_size Output: length of ciphertext
 * @param iv Output: initialization vector used (caller must free, can be NULL)
 * @param iv_size Output: length of IV (can be NULL)
 * @return KMIP_OK on success, error code on failure
 */
int kmip_bio_encrypt_with_context(
    KMIP *ctx,
    BIO *bio,
    char *key_uuid,
    int key_uuid_size,
    uint8 *plaintext,
    int plaintext_size,
    uint8 *additional_data,
    int additional_data_size,
    CryptographicParameters *params,
    uint8 **ciphertext,
    int *ciphertext_size,
    uint8 **iv,
    int *iv_size,
    uint8 **tag,
    int *tag_size
);

/**
 * Decrypt data using a KMIP server with caller-managed context
 *
 * @param ctx Initialized KMIP context
 * @param bio BIO connection to KMIP server
 * @param key_id Unique identifier of the decryption key
 * @param key_id_size Length of key_id string
 * @param ciphertext Data to decrypt
 * @param ciphertext_size Length of ciphertext data
 * @param iv Initialization vector used during encryption
 * @param iv_size Length of IV
 * @param params Cryptographic parameters (should match encryption params)
 * @param plaintext Output: decrypted data (caller must free)
 * @param plaintext_size Output: length of plaintext
 * @return KMIP_OK on success, error code on failure
 */
int kmip_bio_decrypt_with_context(
    KMIP *ctx,
    BIO *bio,
    char *key_id,
    int key_id_size,
    uint8 *ciphertext,
    int ciphertext_size,
    uint8 *additional_data,
    int additional_data_size,
    uint8 *iv,
    int iv_size,
    uint8 *tag,
    int tag_size,
    CryptographicParameters *params,
    uint8 **plaintext,
    int *plaintext_size
);

/*
 * High-Level API Functions for Encrypt/Decrypt Operations
 * These functions automatically create and manage the KMIP context
 */

/**
 * Encrypt data using a KMIP server (simplified API)
 *
 * This is a convenience wrapper that creates and manages the KMIP context
 * automatically. For more control over the context (KMIP version, credentials,
 * error handling), use kmip_bio_encrypt_with_context() instead.
 *
 * @param bio BIO connection to KMIP server
 * @param key_id Unique identifier of the encryption key
 * @param key_id_size Length of key_id string
 * @param plaintext Data to encrypt
 * @param plaintext_size Length of plaintext data
 * @param params Cryptographic parameters (can be NULL for server defaults)
 * @param ciphertext Output: encrypted data (caller must free)
 * @param ciphertext_size Output: length of ciphertext
 * @param iv Output: initialization vector used (caller must free, can be NULL)
 * @param iv_size Output: length of IV (can be NULL)
 * @return KMIP_OK on success, error code on failure
 */
int kmip_bio_encrypt(
    BIO *bio,
    char *key_id,
    int key_id_size,
    uint8 *plaintext,
    int plaintext_size,
    uint8 *additional_data,
    int additional_data_size,
    CryptographicParameters *params,
    uint8 **ciphertext,
    int *ciphertext_size,
    uint8 **iv,
    int *iv_size,
    uint8 **tag,
    int *tag_size
);

/**
 * Decrypt data using a KMIP server (simplified API)
 *
 * This is a convenience wrapper that creates and manages the KMIP context
 * automatically. For more control over the context (KMIP version, credentials,
 * error handling), use kmip_bio_decrypt_with_context() instead.
 *
 * @param bio BIO connection to KMIP server
 * @param key_id Unique identifier of the decryption key
 * @param key_id_size Length of key_id string
 * @param ciphertext Data to decrypt
 * @param ciphertext_size Length of ciphertext data
 * @param iv Initialization vector used during encryption
 * @param iv_size Length of IV
 * @param params Cryptographic parameters (should match encryption params)
 * @param plaintext Output: decrypted data (caller must free)
 * @param plaintext_size Output: length of plaintext
 * @return KMIP_OK on success, error code on failure
 */
int kmip_bio_decrypt(
    BIO *bio,
    char *key_id,
    int key_id_size,
    uint8 *ciphertext,
    int ciphertext_size,
    uint8 *additional_data,
    int additional_data_size,
    uint8 *iv,
    int iv_size,
    uint8 *tag,
    int tag_size,
    CryptographicParameters *params,
    uint8 **plaintext,
    int *plaintext_size
);

#endif  /* KMIP_BIO_H */
