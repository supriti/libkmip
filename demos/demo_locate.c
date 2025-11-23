/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "kmip.h"
#include "kmip_io.h"
#include "kmip_bio.h"
#include "kmip_memset.h"

void
print_help(const char *app)
{
    printf("Usage: %s [flag value | flag] ...\n\n", app);
    printf("Flags:\n");
    printf("-a addr : the IP address of the KMIP server\n");
    printf("-c path : path to client certificate file\n");
    printf("-h      : print this help info\n");
    printf("-k path : path to client key file\n");
    printf("-n name : the name of the key to locate\n");
    printf("-p port : the port number of the KMIP server\n");
    printf("-r path : path to CA certificate file\n");
    printf("-s pass : the password for KMIP server authentication\n");
    printf("-u user : the username for KMIP server authentication\n");
}

int
parse_arguments(int argc, char **argv,
                char **server_address, char **server_port,
                char **client_certificate, char **client_key, char **ca_certificate,
                char **username, char **password,
                char **name,
                int *print_usage)
{
    if(argc <= 1)
    {
        print_help(argv[0]);
        return(-1);
    }

    for(int i = 1; i < argc; i++)
    {
        if(strncmp(argv[i], "-a", 2) == 0)
            *server_address = argv[++i];
        else if(strncmp(argv[i], "-c", 2) == 0)
            *client_certificate = argv[++i];
        else if(strncmp(argv[i], "-h", 2) == 0)
            *print_usage = 1;
        else if(strncmp(argv[i], "-k", 2) == 0)
            *client_key = argv[++i];
        else if(strncmp(argv[i], "-n", 2) == 0)
            *name = argv[++i];
        else if(strncmp(argv[i], "-p", 2) == 0)
            *server_port = argv[++i];
        else if(strncmp(argv[i], "-r", 2) == 0)
            *ca_certificate = argv[++i];
        else if(strncmp(argv[i], "-s", 2) == 0)
            *password = argv[++i];
        else if(strncmp(argv[i], "-u", 2) == 0)
            *username = argv[++i];
        else
        {
            printf("Invalid option: '%s'\n", argv[i]);
            print_help(argv[0]);
            return(-1);
        }
    }

    return(0);
}

int
use_mid_level_api(char *server_address,
                  char *server_port,
                  char *client_certificate,
                  char *client_key,
                  char *ca_certificate,
                  char *username,
                  char *password,
                  char *name)
{
    /* Set up the TLS connection to the KMIP server. */
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());

    printf("\n");
    printf("Loading the client certificate: %s\n", client_certificate);
    if(SSL_CTX_use_certificate_file(ctx, client_certificate, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Loading the client certificate failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }

    printf("Loading the client key: %s\n", client_key);
    if(SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Loading the client key failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }

    printf("Loading the CA certificate: %s\n", ca_certificate);
    if(SSL_CTX_load_verify_locations(ctx, ca_certificate, NULL) != 1)
    {
        fprintf(stderr, "Loading the CA file failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }

    BIO *bio = NULL;
    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        printf("BIO_new_ssl_connect failed\n");
        SSL_CTX_free(ctx);
        return(-1);
    }

    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, server_address);
    BIO_set_conn_port(bio, server_port);

    if(BIO_do_connect(bio) != 1)
    {
        fprintf(stderr, "BIO_do_connect failed\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(-1);
    }

    printf("\n");

    /* Set up the KMIP context. */
    KMIP kmip_context = {0};
    kmip_init(&kmip_context, NULL, 0, KMIP_1_4);

    if(username != NULL && password != NULL)
    {
        TextString u = {0};
        u.value = username;
        u.size = kmip_strnlen_s(username, 50);

        TextString p = {0};
        p.value = password;
        p.size = kmip_strnlen_s(password, 50);

        UsernamePasswordCredential upc = {0};
        upc.username = &u;
        upc.password = &p;

        Credential credential = {0};
        credential.credential_type = KMIP_CRED_USERNAME_AND_PASSWORD;
        credential.credential_value = &upc;

        int cr = kmip_add_credential(&kmip_context, &credential);
        if(cr != KMIP_OK)
        {
            printf("Failed to add credential to the KMIP context.\n");
            BIO_free_all(bio);
            SSL_CTX_free(ctx);
            kmip_destroy(&kmip_context);
            return(cr);
        }
    }

    /* Build a Locate request to find a key by name. */
    TextString name_value = {0};
    name_value.value = name;
    name_value.size = strlen(name);

    Name name_attr_value = {0};
    name_attr_value.value = &name_value;
    name_attr_value.type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;

    Attribute attr = {0};
    kmip_init_attribute(&attr);
    attr.type = KMIP_ATTR_NAME;
    attr.value = &name_attr_value;

    size_t result_count = 0;
    char **unique_ids = NULL;
    int result = kmip_bio_locate_with_context(
        &kmip_context, bio, &attr, 1, &result_count, &unique_ids);

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    /* Handle the response results. */
    printf("\n");
    if(result != KMIP_OK)
    {
        printf("An error occurred while locating the key.\n");
        printf("Error Code: %d\n", result);
        if(kmip_context.error_message)
            printf("Context Error Message: %s\n", kmip_context.error_message);
    }
    else
    {
        printf("Locate request succeeded.\n");
        printf("Found %zu key(s) matching name '%s':\n", result_count, name);
        for(size_t i = 0; i < result_count; i++)
        {
            printf("  [%zu] %s\n", i, unique_ids[i]);
            free(unique_ids[i]);
        }
        free(unique_ids);
    }

    printf("\n");

    kmip_destroy(&kmip_context);
    return(result < 0 ? result : 0);
}

/*
 * Low-level API demo: manually build the Locate request, encode it,
 * send it, decode the response, and print the unique identifiers.
 */
int
use_low_level_api(char *server_address,
                  char *server_port,
                  char *client_certificate,
                  char *client_key,
                  char *ca_certificate,
                  char *name)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());

    if(SSL_CTX_use_certificate_file(ctx, client_certificate, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Loading the client certificate failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }
    if(SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Loading the client key failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }
    if(SSL_CTX_load_verify_locations(ctx, ca_certificate, NULL) != 1)
    {
        fprintf(stderr, "Loading the CA file failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }

    BIO *bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        SSL_CTX_free(ctx);
        return(-1);
    }
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, server_address);
    BIO_set_conn_port(bio, server_port);

    if(BIO_do_connect(bio) != 1)
    {
        fprintf(stderr, "BIO_do_connect failed\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(-1);
    }

    /* Build the Locate request message manually. */
    KMIP kmip_ctx = {0};
    kmip_init(&kmip_ctx, NULL, 0, KMIP_1_4);

    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    uint8 *encoding = kmip_ctx.calloc_func(
        kmip_ctx.state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        kmip_destroy(&kmip_ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(&kmip_ctx, encoding, buffer_total_size);

    /* Set up the Name attribute for the Locate filter. */
    TextString name_value = {0};
    name_value.value = name;
    name_value.size = strlen(name);

    Name name_struct = {0};
    name_struct.value = &name_value;
    name_struct.type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;

    Attribute a = {0};
    kmip_init_attribute(&a);
    a.type = KMIP_ATTR_NAME;
    a.value = &name_struct;

    LocateRequestPayload lrp = {0};
    lrp.attributes = &a;
    lrp.attribute_count = 1;

    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, kmip_ctx.version);

    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    rh.protocol_version = &pv;
    rh.maximum_response_size = kmip_ctx.max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_LOCATE;
    rbi.request_payload = &lrp;

    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;

    int result = kmip_encode_request_message(&kmip_ctx, &rm);
    if(result != KMIP_OK)
    {
        printf("Failed to encode Locate request: %d\n", result);
        kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
        kmip_destroy(&kmip_ctx);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(result);
    }

    int sent = BIO_write(bio, kmip_ctx.buffer,
                         kmip_ctx.index - kmip_ctx.buffer);
    if(sent != kmip_ctx.index - kmip_ctx.buffer)
    {
        printf("BIO_write failed\n");
        kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
        kmip_destroy(&kmip_ctx);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(KMIP_IO_FAILURE);
    }

    kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(&kmip_ctx, NULL, 0);

    printf("Locate request sent. Reading response...\n");

    /* Read response header to get message length. */
    buffer_block_size = 8;
    buffer_total_size = buffer_block_size;
    encoding = kmip_ctx.calloc_func(kmip_ctx.state, 1, buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&kmip_ctx);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }

    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        printf("BIO_read failed for header\n");
        kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
        kmip_destroy(&kmip_ctx);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(KMIP_IO_FAILURE);
    }

    kmip_set_buffer(&kmip_ctx, encoding, buffer_total_size);
    kmip_ctx.index += 4;
    int length = 0;
    kmip_decode_int32_be(&kmip_ctx, &length);
    kmip_rewind(&kmip_ctx);

    kmip_set_buffer(&kmip_ctx, NULL, 0);
    uint8 *extended = kmip_ctx.realloc_func(
        kmip_ctx.state, encoding, buffer_total_size + length);
    if(extended == NULL)
    {
        kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
        kmip_destroy(&kmip_ctx);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    encoding = extended;

    recv = BIO_read(bio, encoding + buffer_total_size, length);
    if(recv != length)
    {
        printf("BIO_read failed for body\n");
        kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size + length);
        kmip_destroy(&kmip_ctx);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(KMIP_IO_FAILURE);
    }

    buffer_total_size += length;
    kmip_set_buffer(&kmip_ctx, encoding, buffer_total_size);

    /* Decode the response message. */
    ResponseMessage resp_m = {0};
    result = kmip_decode_response_message(&kmip_ctx, &resp_m);
    if(result != KMIP_OK)
    {
        printf("Failed to decode Locate response: %d\n", result);
        printf("Context Error: %s\n",
               kmip_ctx.error_message ? kmip_ctx.error_message : "(none)");
        kmip_free_response_message(&kmip_ctx, &resp_m);
        kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
        kmip_destroy(&kmip_ctx);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(result);
    }

    if(resp_m.batch_count != 1)
    {
        printf("Unexpected batch count: %zu\n", resp_m.batch_count);
        result = -1;
    }
    else
    {
        ResponseBatchItem *item = &resp_m.batch_items[0];
        if(item->result_status != KMIP_STATUS_SUCCESS)
        {
            printf("Locate failed with result status: %d\n",
                   item->result_status);
            if(item->result_message)
                printf("Message: %.*s\n",
                       (int)item->result_message->size,
                       item->result_message->value);
            result = -1;
        }
        else
        {
            LocateResponsePayload *pld =
                (LocateResponsePayload *)item->response_payload;
            printf("Locate succeeded. Found %d unique ID(s):\n",
                   pld->unique_identifiers_count);
            for(int i = 0; i < pld->unique_identifiers_count; i++)
            {
                printf("  [%d] %.*s\n", i,
                       (int)pld->unique_identifiers[i].size,
                       pld->unique_identifiers[i].value);
            }
            result = 0;
        }
    }

    kmip_free_response_message(&kmip_ctx, &resp_m);
    kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
    kmip_destroy(&kmip_ctx);
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return(result);
}

int
main(int argc, char **argv)
{
    char *server_address = NULL;
    char *server_port = NULL;
    char *client_certificate = NULL;
    char *client_key = NULL;
    char *ca_certificate = NULL;
    char *username = NULL;
    char *password = NULL;
    char *name = NULL;
    int help = 0;

    int error = parse_arguments(argc, argv,
        &server_address, &server_port,
        &client_certificate, &client_key, &ca_certificate,
        &username, &password,
        &name, &help);
    if(error)
        return(error);
    if(help)
    {
        print_help(argv[0]);
        return(0);
    }

    int result = 0;

    printf("=== Locate using mid-level API ===\n");
    result = use_mid_level_api(
        server_address, server_port,
        client_certificate, client_key, ca_certificate,
        username, password, name);

    printf("\n=== Locate using low-level API ===\n");
    result = use_low_level_api(
        server_address, server_port,
        client_certificate, client_key, ca_certificate,
        name);

    return(result);
}
