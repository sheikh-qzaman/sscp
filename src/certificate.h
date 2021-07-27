#ifndef __CERTIFICATE_H__
#define __CERTIFICATE_H__

#define CERT_PATH               "/usr/share/sscp/cert"
#define CERT_FILE_NAME          "server.crt"
#define KEY_FILE_NAME           "server.crt"
#define CERT_FILE_LEN           200

typedef struct
{
    char    cert_path[CERT_FILE_LEN];
    char    key_path[CERT_FILE_LEN];
    char    root_ca_cert_path[CERT_FILE_LEN];
} t_cert;

void get_cert_path(char *file_path, int file_path_len);
void get_key_path(char *file_path, int file_path_len);

#endif
