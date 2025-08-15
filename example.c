#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "sigv4.h"

int HMAC_SHA256(const unsigned char *data, size_t data_len,
                const unsigned char *key, size_t key_len,
                unsigned char *out, size_t *out_len)
{
    unsigned int len = 0;
    HMAC(EVP_sha256(), key, key_len, data, data_len, out, &len);
    *out_len = len;
    return 0;
}

int main()
{
    aws_sigv4_params_t sigv4_params = {
        .access_key_id = aws_sigv4_string((unsigned char *)"your_access_key"),
        .secret_access_key = aws_sigv4_string((unsigned char *)"your_secret_key"),
        .method = aws_sigv4_string((unsigned char *)"GET"),
        .uri = aws_sigv4_string((unsigned char *)"/"),
        .query_str = aws_sigv4_string((unsigned char *)"encoding-type=url"),
        .host = aws_sigv4_string((unsigned char *)"riptides-sigv4.s3.eu-central-1.amazonaws.com"),
        .region = aws_sigv4_string((unsigned char *)"eu-central-1"),
        .service = aws_sigv4_string((unsigned char *)"s3"),
        .x_amz_date = aws_sigv4_string((unsigned char *)"20250815T071550Z"),
        .hmac_sha256 = HMAC_SHA256,
        .sha256 = (void *)SHA256,
        .sort = qsort,
    };

    char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
    aws_sigv4_header_t auth_header = {
        .value = aws_sigv4_string((unsigned char *)auth_buf)};

    // Initialize sigv4_params and auth_header as needed

    int status = aws_sigv4_sign(&sigv4_params, &auth_header);
    if (status == AWS_SIGV4_OK)
    {
        printf("Signature: %s\n", auth_header.value.data);
    }
    else
    {
        printf("Failed to sign request, status: %d\n", status);
    }

    return 0;
}
