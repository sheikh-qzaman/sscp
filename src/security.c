#include <openssl/ssl.h>

#include <peer.h>
#include <transport.h>
#include <security.h>
#include <certificate.h>
#include <ssl_utils.h>
#include <sscp_debug.h>

int
dtls_ctx_init(SSL_CTX *ctx, t_cert *cert)
{
    if (!SSL_CTX_set_cipher_list(ctx, CIPHER_LIST)) {
        SSCP_ERRLOG("SSL_CTX_set_cipher_list failed [%s]", ssl_get_err_str());
        return ERR_SSL;
    }

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF); // TODO Why cache off?

	if (!SSL_CTX_use_certificate_file(ctx, cert->cert_path, SSL_FILETYPE_PEM)) {
		SSCP_ERRLOG("Certificate %s not found: [%s]", cert_path, ssl_get_err_str());
        return ERR_SSL;
	}
    
    if (!SSL_CTX_use_PrivateKey_file(ctx, cert->key_path, SSL_FILETYPE_PEM)) { // TODO secure key read apis
		SSCP_ERRLOG("Private key %s not found: [%s]", key_path, ssl_get_err_str());
        return ERR_SSL;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
		SSCP_ERRLOG("Certificate doesn't match private key. [%s]", ssl_get_err_str());
        return ERR_SSL;
    }

	if (root_ca_cert_path) {
        SSL_CTX_load_verify_locations(ctx, cert->root_ca_cert_path, NULL);
    }

    // TODO Disable older versions of ssl with set options

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, ssl_verify_cb); // TODO Understand

    //TODO error checks and SSL free if necessary

    return ERR_OK;
}

int
create_dtls_server_ctx(t_wan_intf_node *wan_intf, t_openssl_cb *openssl_cb, SSL_CTX **ctx) // vdaemon_ssl_create_tls_server_ctx
{
    SSL_CTX         *tmp_ctx = NULL;
	int				ret_code = 0;
	uint8_t 		buf[BUFSIZ], *buf_p = buf;
    
    if (!(tmp_ctx = SSL_CTX_new(DTLS_server_method()))) {
        SSCP_ERRLOG("SSL_ctx_new failure for DTLS server.");
        return ERR_SSL;
    }

    /* Always create a new key when using temporary/ephemeral DH parameters. This option must be used to
     * prevent small subgroup attacks, when the DH parameters were not generated using "strong" primes.
     */
    SSL_CTX_set_options(tmp_ctx, SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_tmp_dh(tmp_ctx, wan_intf->dh_params);
    SSL_CTX_set_tmp_ecdh(tmp_ctx, wan_intf->ecdh_paras);

    if (dtls_ctx_init(tmp_ctx) != ERR_OK) {
        SSL_CTX_free(tmp_ctx);
        return ERR_SSL;
    }

    // Read ahead
    SSL_CTX_set_cookie_generate_cb(tmp_ctx, openssl_cb->cookie_generate_cb);
    SSL_CTX_set_cookie_verify_cb(tmp_ctx, openssl_cb->cookie_verify_cb);

    *ctx = tmp_ctx;

    return ERR_OK;
}

int
create_dtls_client_ctx(t_wan_intf_node *wan_intf, t_openssl_cb *openssl_cb, SSL_CTX **ctx, t_cert *cert) // vdaemon_ssl_create_tls_client_ctx
{
    SSL_CTX         *tm_ctx = NULL;

    if (!(tmp_ctx = SSL_CTX_new(DTLS_client_method()))) {
        SSCP_ERRLOG("SSL_ctx_new failure for DTLS client.");
        return ERR_SSL;
    }

    if (dtls_ctx_init(tmp_ctx, cert) != ERR_OK) {
        SSL_CTX_free(tmp_ctx);
        return ERR_SSL;
    }
    
    SSL_CTX_set_verify_depth(tmp_ctx, 2);

    *ctx = tmp_ctx;

    return ERR_OK;
}

int
tls_init(t_wan_intf_node *wan_intf, t_peer *p_ssl_peer, t_conn_mode conn_mode) // vdaemon_ssl_init for UDP
{
    //TODO RAND_poll()
    struct timeval      timeout;
    char                cert_path[CERT_FILE_LEN];
    char                key_path[CERT_FILE_LEN];
    t_openssl_cb        openssl_cb;
    t_cert              cert = { 0 };
    
    // TODO need to revisit
    get_cert_path(cert.cert_path, CERT_FILE_LEN);
    get_key_path(cert.key_path, CERT_FILE_LEN);
 
    // TODO Self peer need to be created here. Need to understand purpose
    if (create_global_peer(p_wan_intf) != 0) {
        SSCP_ERRLOG("Global peer creation failed.");
        return ERR_FAIL;
    }

    openssl_cb = {
        .ssl_verify_cb          = ssl_verify_cb,
        .cookie_generate_cb     = cookie_generate_cb,
        .cookie_verify_cb       = cookie_verify_cb
    };

    if (conn_mode == DTLS_SERVER) {
        create_dtls_server_ctx(wan_intf, &openssl_cb, &wan_intf->dtls_server_ctx);
        init_new_connection(p_ssl_peer, conn_mode);
    } else {
        create_dtls_client_ctx(wan_intf, &openssl_cb, &wan_intf->dtls_client_ctx, &cert);
    }

    return ERR_OK;
}
