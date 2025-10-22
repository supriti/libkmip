/*
 * demo_encrypt.c - Demonstration of KMIP Encrypt/Decrypt operations
 *
 * This demo shows how to use the libkmip encrypt/decrypt API to:
 * 1. Connect to a KMIP server
 * 2. Encrypt plaintext data
 * 3. Decrypt the ciphertext back to plaintext
 *
 * Build: gcc -o demo_encrypt demo_encrypt.c -lkmip -lssl -lcrypto
 * Usage: ./demo_encrypt <server> <port> <cert> <key> <ca> <<key_id>>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "kmip.h"
#include "kmip_io.h"
#include "kmip_bio.h"

void
print_hex(const char *label, uint8 *data, int size)
{
    printf("%s (%d bytes): ", label, size);
    for(int i = 0; i < size && i < 32; i++)
    {
        printf("%02X", data[i]);
    }
    if(size > 32)
    {
        printf("...");
    }
    printf("\n");
}

BIO*
connect_to_kmip_server(
    const char *server,
    const char *port,
    const char *cert_path,
    const char *key_path,
    const char *ca_path)
{
    SSL_CTX *ssl_ctx = NULL;
    BIO *bio = NULL;

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Create SSL context */
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if(ssl_ctx == NULL)
    {
        fprintf(stderr, "Failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return(NULL);
    }

    /* Load client certificate */
    if(SSL_CTX_use_certificate_file(ssl_ctx, cert_path, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Failed to load client certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return(NULL);
    }

    /* Load client private key */
    if(SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Failed to load client private key\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return(NULL);
    }

    /* Verify private key */
    if(SSL_CTX_check_private_key(ssl_ctx) != 1)
    {
        fprintf(stderr, "Private key verification failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return(NULL);
    }

    /* Load CA certificate for server verification */
    if(SSL_CTX_load_verify_locations(ssl_ctx, ca_path, NULL) != 1)
    {
        fprintf(stderr, "Failed to load CA certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return(NULL);
    }

    /* Require server certificate verification */
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    /* Create BIO for connection */
    bio = BIO_new_ssl_connect(ssl_ctx);
    if(bio == NULL)
    {
        fprintf(stderr, "Failed to create BIO\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return(NULL);
    }

    /* Set connection hostname and port */
    char address[256];
    snprintf(address, sizeof(address), "%s:%s", server, port);
    BIO_set_conn_hostname(bio, address);

    /* Connect */
    if(BIO_do_connect(bio) <= 0)
    {
        fprintf(stderr, "Failed to connect to %s\n", address);
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        return(NULL);
    }

    /* Verify server certificate */
    SSL *ssl;
    BIO_get_ssl(bio, &ssl);
    if(SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Server certificate verification failed\n");
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);
        return(NULL);
    }

    printf("Connected to KMIP server at %s\n", address);
    return(bio);
}

int
main(int argc, char **argv)
{
    if(argc < 6)
    {
        fprintf(stderr, "Usage: %s <server> <port> <cert> <key> <ca> <<key_id>>\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Arguments:\n");
        fprintf(stderr, "  server  - KMIP server hostname\n");
        fprintf(stderr, "  port    - KMIP server port (typically 5696)\n");
        fprintf(stderr, "  cert    - Path to client certificate\n");
        fprintf(stderr, "  key     - Path to client private key\n");
        fprintf(stderr, "  ca      - Path to CA certificate\n");
        fprintf(stderr, "  key_id  - (optional) Unique identifier of encryption key\n");
        return(1);
    }

    const char *server = argv[1];
    const char *port = argv[2];
    const char *cert_path = argv[3];
    const char *key_path = argv[4];
    const char *ca_path = argv[5];
    char *key_id = NULL;
    int key_length = 0;
    if (argc == 7)
    {
        key_id = argv[6];
        key_length = kmip_strnlen_s(key_id, 36);
    }


    /* Test data */
    const char *plaintext_str = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$";
    uint8 *plaintext = (uint8 *)plaintext_str;
    int plaintext_size = strlen(plaintext_str);

    const char *context = "{\"aws:s3:arn\": \"arn:aws:s3:::finance-logs-bucket/2023/tax-records.pdf\", \"classification\": \"confidential\", \"encryption_timestamp\": \"2023-10-27T10:00:00Z\"}";
    uint8 *additional_data = (uint8 *)context;
    int additional_data_size = strlen(context);

    printf("\n=== KMIP Encrypt/Decrypt Demo ===\n\n");
    print_hex("Original plaintext", plaintext, plaintext_size);

    /* Connect to KMIP server */
    BIO *bio = connect_to_kmip_server(server, port, cert_path, key_path, ca_path);
    if(bio == NULL)
    {
        fprintf(stderr, "Failed to connect to KMIP server\n");
        return(1);
    }

     /* Create and initialize context */
    KMIP ctx = {0};
    kmip_init(&ctx, NULL, 0, KMIP_1_4);
    int result = 0;

    /* Set up cryptographic parameters */
    CryptographicParameters params = {0};
    kmip_init_cryptographic_parameters(&params);
    params.cryptographic_algorithm = KMIP_CRYPTOALG_AES;
    params.block_cipher_mode = KMIP_BLOCK_GCM;
    params.padding_method = KMIP_PAD_PKCS5;
    params.random_iv = KMIP_TRUE;  /* Request server to generate IV */
    params.tag_length = 16;

    printf("\nCryptographic parameters:\n");
    printf("  Block cipher mode: GCM\n");
    printf("  Padding method: PKCS5\n");
    printf("  Random IV: True (server-generated)\n");

    /* Encrypt the data */
    printf("\n--- Encryption Phase ---\n");
    uint8 *ciphertext = NULL;
    int ciphertext_size = 0;
    uint8 *iv = NULL;
    int iv_size = 0;

    uint8 *tag = NULL;
    int tag_size = 0;

    result = kmip_bio_encrypt_with_context(
        &ctx, bio,
        key_id,
        key_length,
        plaintext,
        plaintext_size,
        additional_data,
        additional_data_size,
        &params,
        &ciphertext,
        &ciphertext_size,
        &iv,
        &iv_size,
        &tag,
        &tag_size);

    if(result != KMIP_OK)
    {
        fprintf(stderr, "Encryption failed with error code: %d (", result);
        kmip_print_error_string(stderr, result); fprintf(stderr, ")\n");
        kmip_destroy(&ctx);
        BIO_free_all(bio);
        return(1);
    }

    printf("Encryption successful!\n");
    print_hex("Ciphertext", ciphertext, ciphertext_size);
    print_hex("IV", iv, iv_size);

    /* Decrypt the data */
    printf("\n--- Decryption Phase ---\n");
    uint8 *decrypted = NULL;
    int decrypted_size = 0;

    result = kmip_bio_decrypt_with_context(
        &ctx, bio,
        key_id,
        key_length,
        ciphertext,
        ciphertext_size,
        additional_data,
        additional_data_size,
        iv,
        iv_size,
        tag,
        tag_size,
        &params,
        &decrypted,
        &decrypted_size);

    if(result != KMIP_OK)
    {
        fprintf(stderr, "Decryption failed with error code: %d (", result);
        kmip_print_error_string(stderr, result); fprintf(stderr, ")\n");
        if(ciphertext != NULL) ctx.free_func(ctx.state, ciphertext);
        if(iv != NULL) ctx.free_func(ctx.state, iv);
        kmip_destroy(&ctx);
        BIO_free_all(bio);
        return(1);
    }

    printf("Decryption successful!\n");
    print_hex("Decrypted plaintext", decrypted, decrypted_size);

    /* Verify roundtrip */
    printf("\n--- Verification ---\n");
    if(decrypted_size == plaintext_size &&
       memcmp(decrypted, plaintext, plaintext_size) == 0)
    {
        printf("✓ SUCCESS: Decrypted data matches original plaintext!\n");
        printf("  Original:  \"%s\"\n", plaintext_str);
        printf("  Decrypted: \"");
        fwrite(decrypted, 1, decrypted_size, stdout);
        printf("\"\n");
    }
    else
    {
        printf("✗ FAILURE: Decrypted data does not match!\n");
        printf("  Expected %d bytes, got %d bytes\n", plaintext_size, decrypted_size);
    }

    /* Cleanup */

    if(ciphertext != NULL) ctx.free_func(ctx.state, ciphertext);
    if(iv != NULL) ctx.free_func(ctx.state, iv);
    if(decrypted != NULL) ctx.free_func(ctx.state, decrypted);
    kmip_destroy(&ctx);
    BIO_free_all(bio);

    printf("\n=== Demo Complete ===\n\n");
    return(0);
}

/*
 * Example output:
 *
 * === KMIP Encrypt/Decrypt Demo ===
 *
 * Original plaintext (52 bytes): 48656C6C6F2C204B4D495021205468697320697320612074657374206D657373616765...
 * Connected to KMIP server at localhost:5696
 *
 * Cryptographic parameters:
 *   Block cipher mode: CBC
 *   Padding method: PKCS5
 *   Random IV: True (server-generated)
 *
 * --- Encryption Phase ---
 * Encryption successful!
 * Ciphertext (64 bytes): 8A3F2E91C45B7D2A6F8E3C1D9B4A7E2C5F1D8A3E6B9C2F5A1D8E4B7C3A9F2E5D...
 * IV (16 bytes): 1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D
 *
 * --- Decryption Phase ---
 * Decryption successful!
 * Decrypted plaintext (52 bytes): 48656C6C6F2C204B4D495021205468697320697320612074657374206D657373616765...
 *
 * --- Verification ---
 * ✓ SUCCESS: Decrypted data matches original plaintext!
 *   Original:  "Hello, KMIP! This is a test message for encryption."
 *   Decrypted: "Hello, KMIP! This is a test message for encryption."
 *
 * === Demo Complete ===
 */
