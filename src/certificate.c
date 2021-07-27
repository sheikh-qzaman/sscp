#include <certificate.h>

void
get_cert_path(char *file_path, int file_path_len)
{
    snprintf(file_path, file_path_len, "%s/%s", CERT_PATH, CERTIFICATE_FILE_NAME);
}

void
get_key_path(char *file_path, int file_path_len)
{
    snprintf(file_path, file_path_len, "%s/%s", CERT_PATH, KEY_FILE_NAME);
}

