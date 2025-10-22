/*
 * demo_activate.c - Demonstration of KMIP Key activation
 *
 * Build: gcc -o demo_activate demo_activate.c -lkmip -lssl -lcrypto
 * Usage: ./demo_activate <server> <port> <cert> <key> <ca> <<key_id>>
 *
 * NOTE: pyKMIP server seems to need the key_id while the KMIP specification defines it as optional
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
        fprintf(stderr, "  key_id  - (optional) Unique identifier of key to activate\n");
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
    (void) key_length;


    printf("\n=== KMIP Key Activation Demo ===\n\n");

    /* Connect to KMIP server */
    BIO *bio = connect_to_kmip_server(server, port, cert_path, key_path, ca_path);
    if(bio == NULL)
    {
        fprintf(stderr, "Failed to connect to KMIP server\n");
        return(1);
    }

     /* Create and initialize context */
    KMIP ctx = {0};
    kmip_init(&ctx, NULL, 0, KMIP_1_2);
    int result = 0;

    // activate key
    result = kmip_bio_activate_with_context( &ctx, bio, key_id);

    if(result != KMIP_OK)
    {
        fprintf(stderr, "Key activation failed with error code: %d (", result);
        kmip_print_error_string(stderr, result); fprintf(stderr, ")\n");
        kmip_destroy(&ctx);
        BIO_free_all(bio);
        return(1);
    }

    printf("Key Activation successful!\n");


    /* Cleanup */

    kmip_destroy(&ctx);
    BIO_free_all(bio);

    printf("\n=== Demo Complete ===\n\n");
    return(0);
}
