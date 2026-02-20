#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kmip.h"
#include "kmip_io.h"
#include "kmip_bio.h"

void print_help(const char *app) {
    printf("Usage: %s -a <addr> -p <port> -c <cert> -k <key> -r <ca> -i <uuid>\n", app);
}

int main(int argc, char **argv) {
    // FORCE UNBUFFERED OUTPUT so we see debug lines immediately
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    char *server_address = "127.0.0.1", *server_port = "5696";
    char *client_cert = NULL, *client_key = NULL, *ca_cert = NULL, *uuid = NULL;

    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-a") == 0) server_address = argv[++i];
        else if(strcmp(argv[i], "-p") == 0) server_port = argv[++i];
        else if(strcmp(argv[i], "-c") == 0) client_cert = argv[++i];
        else if(strcmp(argv[i], "-k") == 0) client_key = argv[++i];
        else if(strcmp(argv[i], "-r") == 0) ca_cert = argv[++i];
        else if(strcmp(argv[i], "-i") == 0) uuid = argv[++i];
    }

    if(!client_cert || !client_key || !ca_cert || !uuid) {
        print_help(argv[0]);
        return 1;
    }

    printf("Connecting to %s:%s...\n", server_address, server_port);

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if(!SSL_CTX_use_certificate_file(ssl_ctx, client_cert, SSL_FILETYPE_PEM) ||
       !SSL_CTX_use_PrivateKey_file(ssl_ctx, client_key, SSL_FILETYPE_PEM) ||
       !SSL_CTX_load_verify_locations(ssl_ctx, ca_cert, NULL)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    BIO *bio = BIO_new_ssl_connect(ssl_ctx);
    BIO_set_conn_hostname(bio, server_address);
    BIO_set_conn_port(bio, server_port);

    if(BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Connection failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    KMIP ctx = {0};
    kmip_init(&ctx, NULL, 0, KMIP_2_0);

    printf("\n--- Step 1: Revoking Key (%s) ---\n", uuid);
    // Reason 6 = Cessation of Operation
    int revoke_res = kmip_bio_revoke_with_context(&ctx, bio, uuid, strlen(uuid), 6);
    
    if (revoke_res != 0) {
        fprintf(stderr, "Revoke Failed. Status: %d. Error: %s\n", revoke_res, kmip_last_message());
        // We do not stop here for debugging purposes, but in production, you should.
    } else {
        printf("Revoke Successful (Key is now Deactivated)\n");
    }

    printf("\n--- Step 2: Destroying Key (%s) ---\n", uuid);
    kmip_reset(&ctx);
    int destroy_res = kmip_bio_destroy_symmetric_key_with_context(&ctx, bio, uuid, strlen(uuid));

    if (destroy_res == 0) {
        printf("\nSUCCESS: Key fully revoked and destroyed.\n");
    } else {
        fprintf(stderr, "\nFAILURE: Destroy returned Status %d\n", destroy_res);
        fprintf(stderr, "Reason from server: %s\n", kmip_last_message());
    }

    BIO_free_all(bio);
    SSL_CTX_free(ssl_ctx);
    kmip_destroy(&ctx);
    return 0;
}