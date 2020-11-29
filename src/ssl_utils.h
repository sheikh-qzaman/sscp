#ifndef __SSL_UTILS_H__
#define __SSL_UTILS_H__

#include <openssl/ssl.h>

#include <globals.h>
#include <transport.h>

typedef struct
{
    int         (*ssl_verify_cb) (int pre_verify_ok, X509_STORE_CTX *ctx);
    int         (*cookie_generate_cb) (SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
    int         (*cookie_verify_cb) (SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);
} t_openssl_cb;

const char* ssl_get_err_str();
void openssl_init(void);
int ssl_verify_cb (int pre_verify_ok, X509_STORE_CTX *ctx);
int cookie_generate_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
int cookie_verify_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);
e_err create_ssl_server_ctx();
e_err create_ssl_client_ctx();

#endif
