#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>

#include <sscp.h>
#include <ssl_utils.h> 
#include <logging.h>

#define COOKIE_SECRET_LENGTH            16

// TODO use eventbase to increment cookie
unsigned int            cookie_epoch_id = 0; // Monotonically incrementing number
unsigned char           cookie_secret[COOKIE_SECRET_LENGTH];

union {
    struct sockaddr_storage ss;
    struct sockaddr_in6 s6;
    struct sockaddr_in s4;
} peer;

void
openssl_init(void)
{
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms(); 
}

/*
DH*
vdaemon_setup_dh_params()
{
    int             	chosen_dh_param;
    DH					*dh;
    struct timespec 	ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    chosen_dh_param = (rand() % 23);
    SSCP_DEBUGLOG("chose dh params index dd= %d", chosen_dh_param);

    dh = get_dh2048_fn_array[chosen_dh_param]();
    if (!dh) {
        SSCP_ERRLOG("chose dh params index dd = %d returned NULL", chosen_dh_param);
    }

    return dh;
}

int
cookie_generate_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    memcpy(cookie, "cookie", 6);
    cookie_len = 6;
    return 1;
    // TODO remove dummy cookie with below code

    unsigned char               *cookie_str, hash[EVP_MAX_MD_SIZE];
    unsigned int                length = sizeof(cookie_epoch_id), hashlen;

    BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer)

    if (peer.ss.ss_family == AF_INET) {
        length += (sizeof(struct in_addr) + sizeof(in_port_t));
    } else {
        length += (sizeof(struct in6_addr) + sizeof(in_port_t));
    }

    cookie_str = calloc(1, 0, sizeof(length));
    if (cookie_str == NULL) {
        SSCP_ERRLOG("Unable to allocate for the cookie_str");
        return ERR_SSL;
    }

    if (peer.ss.ss_family == AF_INET) {
        memcpy(cookie_str, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
        memcpy(cookie_str + sizeof(peer.s4.sin_port), &peer.s4.sin_addr, sizeof(struct in_addr));
        memcpy(cookie_str + sizeof(peer.s4.sin_port) + sizeof(struct in_addr), &cookie_epoch_id, sizeof(cookie_epoch_id));
    } else {
        memcpy(cookie_str, &peer.s6.sin6_port, sizeof(peer.s6.sin6_port));
        memcpy(cookie_str + sizeof(peer.s6.sin6_port), peer.s6.sin6_addr.s6_addr, sizeof(struct in6_addr));
        memcpy(cookie_str + sizeof(peer.s6.sin6_port) + sizeof(struct in6_addr), &cookie_epoch_id, sizeof(cookie_epoch_id));
    }

    HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH, (const unsigned char*) cookie_str, length, hash, &hashlen);
    free(cookie_str);

    memcpy(cookie, hash, hashlen);
    *cookie_len = hashlen;

    return 1;
}

int cookie_verify_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    //TODO
    return 0;
}


// TODO Nedd to understand return type and static char
const char*
ssl_get_err_str() {
    static char err_str[1024];
    uint32_t    err = ERR_get_error();

    if (!ERR_error_string(err, err_str)) {
        return "Unknown OpenSSL error.";
    }

    return err_str;
}

int
ssl_verify_cb (int pre_verify_ok, X509_STORE_CTX *ctx)
{
    if (pre_verify_ok == 0) {
        SSCP_ERRLOG("Verify failed: self signed certificate! No need to panic!!");
    }

    return 1;
}

int
ssl_read_cert(const char *path, X509 **req)
{
    FILE *fp = NULL;

    if (!(fp = fopen(path, "rb"))) {
        SSCP_ERRLOG("Error opening certficate file %s", path);
        return 1;
    }

    if (!(*req = PEM_read_X509(fp, NULL, NULL, NULL))) {
        SSCP_ERRLOG("PEM_read_X509 failed [%s]", ssl_get_err_str());
        fclose(fp);
        return 1;
    }

    fclose(fp);

    return 0;
}
*/

static int
cert_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    X509        *err_cert;
    char        buf[256];
    int         err, depth;

    SSCP_DEBUGLOG("certify verify...");

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    if (err) {
        printf("Certificate ERROR: [ %s ] \nPlease check certificate [ %s ] depth : [ %d ] \n",
                    X509_verify_cert_error_string(err), buf, depth);
    }

    return preverify_ok;
}

e_err
create_ssl_ctx()
{
    /* Initialize the OpenSSL library */
    SSL_load_error_strings();
    SSL_library_init();

    /* We MUST have entropy, or else there's no point to crypto. */
    if (!RAND_poll()) {
        return ERR_SSL;
    }

    return ERR_OK;
}

e_err
create_ssl_client_ctx()
{
    t_cpmgr_ctx     *p_cpmgr_ctx = cpmgr_get_ctx();
    /*
     * An SSL_CTX object will be a factory for producing SSL connection objects. This context allows us to set connection configuration
     * parameters before the connection is made, such as protocol version, certificate information, and verification requirements.
     */
    SSL_CTX         *ssl_client_ctx;
    int             ret;

    ssl_client_ctx = SSL_CTX_new(SSLv23_client_method());

    /*
     * This function sets the maximum allowable depth for peer certificates. In other words, it limits the number of certificates that we are
     * willing to verify in order to ensure the chain is trusted. For example, if the depth was set to four and six certificates are present
     * in the chain to reach the trusted certificate, the verification would fail because the required depth would be too great.
     */
    SSL_CTX_set_verify_depth(ssl_client_ctx, 1);

    SSL_CTX_set_ecdh_auto(ssl_client_ctx, 1);

    // ca certificate
    if (!SSL_CTX_load_verify_locations(ssl_client_ctx, "rootCA.crt",NULL)) { 
        SSCP_ERRLOG("Coult not load CA certificate.");
        return ERR_SSL;
    }

    /*
     * OpenSSL has internal callback to verify the client provided certificate. However this callback provide customization, i.e. accepting an
     * expired certificate for example. The second argument is flag which can be logical ORed. These are:
     * SSL_VERIFY_NONE: When the context is being used in server mode, no request for a certificate will be sent to the client, and the client
     * should not send a certificate. 
     * SSL_VERIFY_PEER: When the context is being used in server mode, a request for a certificate will be sent to the client. The client may opt
     * to ignore the request, but if a certificate is sent back, it will be verified. If the verification fails, the handshake will be terminated
     * immediately. When the context is being used in client mode, if the server sends a certificate, it will be verified. If the verification fails,
     * the handshake will be terminated immediately. The only time that a server would not send a certificate is when an anonymous cipher is in use.
     * Anonymous ciphers are disabled by default. Any other flags combined with this one in client mode are ignored.
     * SSL_VERIFY_FAIL_IF_NO_PEER_CERT: If the context is not being used in server mode or if SSL_VERIFY_PEER is not set, this flag is ignored.
     * Use of this flag will cause the handshake to terminate immediately if no certificate is provided by the client.
     * SSL_VERIFY_CLIENT_ONCE: If the context is not being used in server mode or if SSL_VERIFY_PEER is not set, this flag is ignored. Use of this flag
     * will prevent the server from requesting a certificate from the client in the case of a renegotiation. A certificate will still be requested during
     * the initial handshake.
     */
    SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, cert_verify_callback);

    p_cpmgr_ctx->ssl_client_ctx = ssl_client_ctx;

    return ERR_OK;
}

e_err
create_ssl_server_ctx()
{
    t_cpmgr_ctx     *p_cpmgr_ctx = cpmgr_get_ctx();
    SSL_CTX         *ssl_server_ctx;

    ssl_server_ctx = SSL_CTX_new(SSLv23_server_method());

    SSL_CTX_set_ecdh_auto(ssl_server_ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ssl_server_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        SSCP_DEBUGLOG("Cant' open certificate.");
        //ERR_print_errors_fp(stderr);
        return ERR_SSL;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_server_ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
        SSCP_DEBUGLOG("Cant' open private key.");
        //ERR_print_errors_fp(stderr);
        return ERR_SSL;
    }

    //SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);
    p_cpmgr_ctx->ssl_server_ctx = ssl_server_ctx;

    return ERR_OK;
}


