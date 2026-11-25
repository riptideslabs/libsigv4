#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <check.h>

#include "sigv4.h"

/* the signer works out of caller-owned buffers; ~8 KB, so keep it out of
   automatic storage -- on a kernel stack it would not fit at all */
static aws_sigv4_scratch_t scratch;

int HMAC_SHA256(const unsigned char *data, size_t data_len,
                const unsigned char *key, size_t key_len,
                unsigned char *out, size_t *out_len)
{
  unsigned int len = 0;
  char *ac = HMAC(EVP_sha256(), key, key_len, data, data_len, out, &len);
  *out_len = len;
  return (ac != NULL) ? 0 : -1;
}

START_TEST(AwsSigv4Test_AwsSigv4Sign)
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
      .scratch = &scratch,
  };

  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
  aws_sigv4_header_t auth_header = {
      .value = aws_sigv4_string((unsigned char *)auth_buf)};

  int rc = aws_sigv4_sign(&sigv4_params, &auth_header);
  const unsigned char *expected_auth_header_name = "Authorization";
  const unsigned char *expected_auth_header_value =
      "AWS4-HMAC-SHA256 Credential=your_access_key/20250815/eu-central-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=d3ed09f6c93b21cc6301b94fafadbe0b3f2b3d93a7540f5009c41c431a1c6312";
  int expected_len = strlen(expected_auth_header_value);
  ck_assert_int_eq(rc, AWS_SIGV4_OK);

  ck_assert_pstr_eq(auth_header.key.data, expected_auth_header_name);
  ck_assert_int_eq(auth_header.key.len, strlen(expected_auth_header_name));
  ck_assert_mem_eq(auth_header.key.data, expected_auth_header_name, strlen(expected_auth_header_name));

  ck_assert_pstr_eq(auth_header.value.data, expected_auth_header_value);
  ck_assert_int_eq(auth_header.value.len, expected_len);
  ck_assert_mem_eq(auth_header.value.data, expected_auth_header_value, expected_len);
}
END_TEST

/* every additional header must end up in both the canonical and the signed headers,
   otherwise S3 rejects the request with "There were headers present in the request
   which were not signed" (e.g. x-amz-copy-source on CopyObject) */
START_TEST(AwsSigv4Test_AdditionalHeadersAreSigned)
{
  aws_sigv4_params_t sigv4_params = {
      .access_key_id = aws_sigv4_string((unsigned char *)"AKIDEXAMPLE"),
      .secret_access_key = aws_sigv4_string((unsigned char *)"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
      .method = aws_sigv4_string((unsigned char *)"PUT"),
      .uri = aws_sigv4_string((unsigned char *)"/Logo_dark2.png"),
      .host = aws_sigv4_string((unsigned char *)"riptides-logos.s3.eu-central-1.amazonaws.com"),
      .region = aws_sigv4_string((unsigned char *)"eu-central-1"),
      .service = aws_sigv4_string((unsigned char *)"s3"),
      .x_amz_date = aws_sigv4_string((unsigned char *)"20260803T120000Z"),
      .headers = {
          {
              .key = aws_sigv4_string((unsigned char *)"x-amz-copy-source"),
              .value = aws_sigv4_string((unsigned char *)"/riptides-logos/Logo_dark.png"),
          },
          {
              .key = aws_sigv4_string((unsigned char *)"x-amz-content-sha256"),
              .value = aws_sigv4_string((unsigned char *)"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
          },
      },
      .num_headers = 2,
      .hmac_sha256 = HMAC_SHA256,
      .sha256 = (void *)SHA256,
      .sort = qsort,
      .scratch = &scratch,
  };

  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
  aws_sigv4_header_t auth_header = {
      .value = aws_sigv4_string((unsigned char *)auth_buf)};

  int rc = aws_sigv4_sign(&sigv4_params, &auth_header);
  const unsigned char *expected_auth_header_value =
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260803/eu-central-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-copy-source;x-amz-date, Signature=bd8e0ec929d2846e7ea9be3ac601e143bf6f02a23c476f0bd54d9c5a114eac1a";
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  ck_assert_pstr_eq(auth_header.value.data, expected_auth_header_value);
}
END_TEST

/* on a common prefix the shorter header name sorts first, so SSE-KMS requests keep
   x-amz-server-side-encryption ahead of x-amz-server-side-encryption-aws-kms-key-id */
START_TEST(AwsSigv4Test_PrefixHeaderNamesAreOrdered)
{
  aws_sigv4_params_t sigv4_params = {
      .access_key_id = aws_sigv4_string((unsigned char *)"AKIDEXAMPLE"),
      .secret_access_key = aws_sigv4_string((unsigned char *)"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
      .method = aws_sigv4_string((unsigned char *)"PUT"),
      .uri = aws_sigv4_string((unsigned char *)"/obj.txt"),
      .host = aws_sigv4_string((unsigned char *)"riptides-logos.s3.eu-central-1.amazonaws.com"),
      .region = aws_sigv4_string((unsigned char *)"eu-central-1"),
      .service = aws_sigv4_string((unsigned char *)"s3"),
      .x_amz_date = aws_sigv4_string((unsigned char *)"20260803T120000Z"),
      .payload = aws_sigv4_string((unsigned char *)"abc"),
      .unsigned_payload = true,
      .headers = {
          {
              .key = aws_sigv4_string((unsigned char *)"x-amz-server-side-encryption"),
              .value = aws_sigv4_string((unsigned char *)"aws:kms"),
          },
          {
              .key = aws_sigv4_string((unsigned char *)"x-amz-server-side-encryption-aws-kms-key-id"),
              .value = aws_sigv4_string((unsigned char *)"arn:aws:kms:eu-central-1:1:key/abc"),
          },
          {
              .key = aws_sigv4_string((unsigned char *)"x-amz-content-sha256"),
              .value = aws_sigv4_string((unsigned char *)"UNSIGNED-PAYLOAD"),
          },
          {
              .key = aws_sigv4_string((unsigned char *)"content-length"),
              .value = aws_sigv4_string((unsigned char *)"3"),
          },
      },
      .num_headers = 4,
      .hmac_sha256 = HMAC_SHA256,
      .sha256 = (void *)SHA256,
      .sort = qsort,
      .scratch = &scratch,
  };

  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
  aws_sigv4_header_t auth_header = {
      .value = aws_sigv4_string((unsigned char *)auth_buf)};

  int rc = aws_sigv4_sign(&sigv4_params, &auth_header);
  const unsigned char *expected_auth_header_value =
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260803/eu-central-1/s3/aws4_request, SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id, Signature=030bc849566322f211383dcab0b9dab63c6e29eca34786d6b303f601cb734f0c";
  ck_assert_int_eq(rc, AWS_SIGV4_OK);
  ck_assert_pstr_eq(auth_header.value.data, expected_auth_header_value);
}
END_TEST

/* headers that do not fit into the internal buffers must fail the signing instead of
   writing past them */
START_TEST(AwsSigv4Test_TooLargeCanonicalRequestFails)
{
  static char keys[AWS_SIGV4_MAX_NUM_HEADERS][64];
  static char values[AWS_SIGV4_MAX_NUM_HEADERS][1024];

  aws_sigv4_params_t sigv4_params = {
      .access_key_id = aws_sigv4_string((unsigned char *)"AKIDEXAMPLE"),
      .secret_access_key = aws_sigv4_string((unsigned char *)"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
      .method = aws_sigv4_string((unsigned char *)"PUT"),
      .uri = aws_sigv4_string((unsigned char *)"/obj.txt"),
      .host = aws_sigv4_string((unsigned char *)"riptides-logos.s3.eu-central-1.amazonaws.com"),
      .region = aws_sigv4_string((unsigned char *)"eu-central-1"),
      .service = aws_sigv4_string((unsigned char *)"s3"),
      .x_amz_date = aws_sigv4_string((unsigned char *)"20260803T120000Z"),
      .unsigned_payload = true,
      .hmac_sha256 = HMAC_SHA256,
      .sha256 = (void *)SHA256,
      .sort = qsort,
      .scratch = &scratch,
  };

  unsigned int i;
  for (i = 0; i < AWS_SIGV4_MAX_NUM_HEADERS; i++)
  {
    snprintf(keys[i], sizeof(keys[i]), "x-amz-meta-header-number-%02u", i);
    memset(values[i], 'v', sizeof(values[i]) - 1);
    values[i][sizeof(values[i]) - 1] = '\0';
    sigv4_params.headers[i].key = aws_sigv4_string((unsigned char *)keys[i]);
    sigv4_params.headers[i].value = aws_sigv4_string((unsigned char *)values[i]);
    sigv4_params.num_headers++;
  }

  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
  aws_sigv4_header_t auth_header = {
      .value = aws_sigv4_string((unsigned char *)auth_buf)};

  int rc = aws_sigv4_sign(&sigv4_params, &auth_header);
  ck_assert_int_eq(rc, AWS_SIGV4_BUFFER_OVERFLOW_ERROR);
}
END_TEST

/* region, service and "AWS4" + secret each go through a 64-byte buffer when the
   signing key is derived; one byte too long must fail instead of writing past it */
START_TEST(AwsSigv4Test_TooLongSigningKeyPartsFail)
{
  static char long_part[65];
  static char fits_part[64];
  memset(long_part, 'a', sizeof(long_part) - 1);
  memset(fits_part, 'a', sizeof(fits_part) - 1);

  aws_sigv4_params_t base = {
      .access_key_id = aws_sigv4_string((unsigned char *)"AKIDEXAMPLE"),
      .secret_access_key = aws_sigv4_string((unsigned char *)"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
      .method = aws_sigv4_string((unsigned char *)"GET"),
      .uri = aws_sigv4_string((unsigned char *)"/"),
      .host = aws_sigv4_string((unsigned char *)"riptides-logos.s3.eu-central-1.amazonaws.com"),
      .region = aws_sigv4_string((unsigned char *)"eu-central-1"),
      .service = aws_sigv4_string((unsigned char *)"s3"),
      .x_amz_date = aws_sigv4_string((unsigned char *)"20260803T120000Z"),
      .unsigned_payload = true,
      .hmac_sha256 = HMAC_SHA256,
      .sha256 = (void *)SHA256,
      .sort = qsort,
      .scratch = &scratch,
  };
  aws_sigv4_params_t sigv4_params;
  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN];
  aws_sigv4_header_t auth_header;

#define SIGN_WITH(field, val, expected_rc)                                        \
  do                                                                              \
  {                                                                               \
    sigv4_params = base;                                                          \
    sigv4_params.field = aws_sigv4_string((unsigned char *)(val));                \
    memset(auth_buf, 0, sizeof(auth_buf));                                        \
    auth_header = (aws_sigv4_header_t){.value = {.data = (unsigned char *)auth_buf}}; \
    ck_assert_int_eq(aws_sigv4_sign(&sigv4_params, &auth_header), (expected_rc)); \
  } while (0)

  SIGN_WITH(region, fits_part, AWS_SIGV4_OK);
  SIGN_WITH(region, long_part, AWS_SIGV4_BUFFER_OVERFLOW_ERROR);
  SIGN_WITH(service, fits_part, AWS_SIGV4_OK);
  SIGN_WITH(service, long_part, AWS_SIGV4_BUFFER_OVERFLOW_ERROR);
  SIGN_WITH(secret_access_key, fits_part + 4, AWS_SIGV4_OK);
  SIGN_WITH(secret_access_key, long_part + 4, AWS_SIGV4_BUFFER_OVERFLOW_ERROR);

#undef SIGN_WITH
}
END_TEST

/* the scratch buffers are mandatory: without them the signer has nowhere to build the
   canonical request, so it must refuse rather than dereference NULL */
START_TEST(AwsSigv4Test_MissingScratchIsRejected)
{
  aws_sigv4_params_t sigv4_params = {
      .access_key_id = aws_sigv4_string((unsigned char *)"AKIDEXAMPLE"),
      .secret_access_key = aws_sigv4_string((unsigned char *)"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
      .method = aws_sigv4_string((unsigned char *)"GET"),
      .uri = aws_sigv4_string((unsigned char *)"/"),
      .host = aws_sigv4_string((unsigned char *)"riptides-logos.s3.eu-central-1.amazonaws.com"),
      .region = aws_sigv4_string((unsigned char *)"eu-central-1"),
      .service = aws_sigv4_string((unsigned char *)"s3"),
      .x_amz_date = aws_sigv4_string((unsigned char *)"20260803T120000Z"),
      .hmac_sha256 = HMAC_SHA256,
      .sha256 = (void *)SHA256,
      .sort = qsort,
      .scratch = NULL,
  };

  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
  aws_sigv4_header_t auth_header = {
      .value = aws_sigv4_string((unsigned char *)auth_buf)};

  int rc = aws_sigv4_sign(&sigv4_params, &auth_header);
  ck_assert_int_eq(rc, AWS_SIGV4_INVALID_INPUT_ERROR);
}
END_TEST

/* a query string with more components than the parser can hold must fail the signing:
   silently dropping the tail would write past the scratch array and produce a
   canonical request that does not match what the request actually carries */
START_TEST(AwsSigv4Test_TooManyQueryParamsFails)
{
  static char query[8 * 1024];
  char *w = query;
  int i;
  for (i = 0; i < AWS_SIGV4_MAX_NUM_QUERY_COMPONENTS + 5; i++)
  {
    w += snprintf(w, sizeof(query) - (w - query), "%sk%02d=v%02d", i ? "&" : "", i, i);
  }

  aws_sigv4_params_t sigv4_params = {
      .access_key_id = aws_sigv4_string((unsigned char *)"AKIDEXAMPLE"),
      .secret_access_key = aws_sigv4_string((unsigned char *)"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
      .method = aws_sigv4_string((unsigned char *)"GET"),
      .uri = aws_sigv4_string((unsigned char *)"/"),
      .query_str = aws_sigv4_string((unsigned char *)query),
      .host = aws_sigv4_string((unsigned char *)"riptides-logos.s3.eu-central-1.amazonaws.com"),
      .region = aws_sigv4_string((unsigned char *)"eu-central-1"),
      .service = aws_sigv4_string((unsigned char *)"s3"),
      .x_amz_date = aws_sigv4_string((unsigned char *)"20260803T120000Z"),
      .unsigned_payload = true,
      .hmac_sha256 = HMAC_SHA256,
      .sha256 = (void *)SHA256,
      .sort = qsort,
      .scratch = &scratch,
  };

  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
  aws_sigv4_header_t auth_header = {
      .value = aws_sigv4_string((unsigned char *)auth_buf)};

  int rc = aws_sigv4_sign(&sigv4_params, &auth_header);
  ck_assert_int_eq(rc, AWS_SIGV4_BUFFER_OVERFLOW_ERROR);
}
END_TEST

static const aws_sigv4_params_t valid_params = {
    .access_key_id = {(unsigned char *)"AKIDEXAMPLE", 11},
    .secret_access_key = {(unsigned char *)"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", 40},
    .method = {(unsigned char *)"GET", 3},
    .uri = {(unsigned char *)"/", 1},
    .host = {(unsigned char *)"riptides-logos.s3.eu-central-1.amazonaws.com", 44},
    .region = {(unsigned char *)"eu-central-1", 12},
    .service = {(unsigned char *)"s3", 2},
    .x_amz_date = {(unsigned char *)"20260803T120000Z", 16},
    .unsigned_payload = true,
    .hmac_sha256 = HMAC_SHA256,
    .sha256 = (void *)SHA256,
    .sort = qsort,
    .scratch = &scratch,
};

/* num_headers is the caller's to set; a count beyond the headers array must be
   refused instead of walking past it */
START_TEST(AwsSigv4Test_TooManyHeadersRejected)
{
  aws_sigv4_params_t sigv4_params = valid_params;
  unsigned int i;
  for (i = 0; i < AWS_SIGV4_MAX_NUM_HEADERS; i++)
  {
    sigv4_params.headers[i].key = aws_sigv4_string((unsigned char *)"x-amz-meta-a");
    sigv4_params.headers[i].value = aws_sigv4_string((unsigned char *)"v");
  }
  sigv4_params.num_headers = AWS_SIGV4_MAX_NUM_HEADERS + 1;

  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
  aws_sigv4_header_t auth_header = {
      .value = aws_sigv4_string((unsigned char *)auth_buf)};

  ck_assert_int_eq(aws_sigv4_sign(&sigv4_params, &auth_header), AWS_SIGV4_INVALID_INPUT_ERROR);
}
END_TEST

static int HMAC_SHA256_Failing(const unsigned char *data, size_t data_len,
                               const unsigned char *key, size_t key_len,
                               unsigned char *out, size_t *out_len)
{
  (void)data, (void)data_len, (void)key, (void)key_len, (void)out;
  *out_len = 0;
  return -1;
}

/* a wrong digest, e.g. SHA-512 plugged in by mistake: 64 bytes, not 32 */
static int HMAC_SHA512(const unsigned char *data, size_t data_len,
                       const unsigned char *key, size_t key_len,
                       unsigned char *out, size_t *out_len)
{
  unsigned int len = 0;
  unsigned char *ac = HMAC(EVP_sha512(), key, key_len, data, data_len, out, &len);
  *out_len = len;
  return (ac != NULL) ? 0 : -1;
}

/* the HMAC callback's result and reported length decide how much is copied into the
   signer's fixed buffers, so a failing or wrong-sized HMAC must fail the signing */
START_TEST(AwsSigv4Test_BadHmacRejected)
{
  aws_sigv4_params_t sigv4_params;
  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
  aws_sigv4_header_t auth_header;

  sigv4_params = valid_params;
  sigv4_params.hmac_sha256 = HMAC_SHA256_Failing;
  auth_header = (aws_sigv4_header_t){.value = {.data = (unsigned char *)auth_buf}};
  ck_assert_int_eq(aws_sigv4_sign(&sigv4_params, &auth_header), AWS_SIGV4_INVALID_INPUT_ERROR);

  sigv4_params = valid_params;
  sigv4_params.hmac_sha256 = HMAC_SHA512;
  auth_header = (aws_sigv4_header_t){.value = {.data = (unsigned char *)auth_buf}};
  ck_assert_int_eq(aws_sigv4_sign(&sigv4_params, &auth_header), AWS_SIGV4_INVALID_INPUT_ERROR);
}
END_TEST

/* like snprintf: n bounds everything written, terminator included */
START_TEST(AwsSigv4Test_SnprintfStaysWithinN)
{
  unsigned char buf[8];
  unsigned char *end;

  memset(buf, 'x', sizeof(buf));
  end = aws_sigv4_snprintf(buf, 4, "abcdef");
  ck_assert_ptr_eq(end, buf + 3);
  ck_assert_mem_eq(buf, "abc\0x", 5);

  memset(buf, 'x', sizeof(buf));
  end = aws_sigv4_snprintf(buf, 0, "abcdef");
  ck_assert_ptr_eq(end, buf);
  ck_assert_int_eq(buf[0], 'x');

  memset(buf, 'x', sizeof(buf));
  end = aws_sigv4_snprintf(buf, sizeof(buf), "abc");
  ck_assert_ptr_eq(end, buf + 3);
  ck_assert_mem_eq(buf, "abc\0x", 5);

  /* an empty %V adds nothing; the rest of fmt and the terminator still follow */
  aws_sigv4_str_t empty = {0};
  memset(buf, 'x', sizeof(buf));
  end = aws_sigv4_snprintf(buf, sizeof(buf), "a%Vbc", &empty);
  ck_assert_ptr_eq(end, buf + 3);
  ck_assert_mem_eq(buf, "abc\0x", 5);
}
END_TEST

/* get_credential_scope() and get_string_to_sign() take last as the exclusive end of
   the output buffer, so nothing may be written there */
START_TEST(AwsSigv4Test_ExportedBuildersStayBeforeLast)
{
  aws_sigv4_params_t sigv4_params = valid_params;
  static const char scope[] = "20260803/eu-central-1/s3/aws4_request";
  unsigned char buf[256];
  aws_sigv4_str_t out;

  /* room for the text and its terminator: nothing is lost */
  memset(buf, 'x', sizeof(buf));
  out = (aws_sigv4_str_t){.data = buf};
  get_credential_scope(&sigv4_params, &out, buf + sizeof(scope));
  ck_assert_uint_eq(out.len, sizeof(scope) - 1);
  ck_assert_mem_eq(buf, scope, sizeof(scope));
  ck_assert_int_eq(buf[sizeof(scope)], 'x');

  /* shorter than the yyyymmdd date */
  memset(buf, 'x', sizeof(buf));
  out = (aws_sigv4_str_t){.data = buf};
  get_credential_scope(&sigv4_params, &out, buf + 5);
  ck_assert_uint_lt(out.len, 5);
  ck_assert_int_eq(buf[5], 'x');

  aws_sigv4_str_t date = sigv4_params.x_amz_date;
  aws_sigv4_str_t credential_scope = {(unsigned char *)scope, sizeof(scope) - 1};
  aws_sigv4_str_t canonical_request = aws_sigv4_string((unsigned char *)"GET\n/\n");
  /* "AWS4-HMAC-SHA256\n" date "\n" scope "\n" hex(sha256) */
  size_t sts_len = 17 + date.len + 1 + credential_scope.len + 1 + 64;

  memset(buf, 'x', sizeof(buf));
  out = (aws_sigv4_str_t){.data = buf};
  ck_assert_int_eq(get_string_to_sign(&sigv4_params, &date, &credential_scope,
                                      &canonical_request, &out, buf + sts_len),
                   AWS_SIGV4_OK);
  ck_assert_uint_eq(out.len, sts_len);
  ck_assert_int_eq(buf[sts_len], 'x');

  memset(buf, 'x', sizeof(buf));
  out = (aws_sigv4_str_t){.data = buf};
  ck_assert_int_eq(get_string_to_sign(&sigv4_params, &date, &credential_scope,
                                      &canonical_request, &out, buf + 20),
                   AWS_SIGV4_BUFFER_OVERFLOW_ERROR);
  ck_assert_int_eq(buf[20], 'x');
}
END_TEST

/* only a header named exactly x-amz-content-sha256 replaces the one added for S3;
   a name that is merely a prefix of it must not */
START_TEST(AwsSigv4Test_ContentSha256PrefixIsNotTheHeader)
{
  aws_sigv4_params_t sigv4_params = valid_params;
  sigv4_params.headers[0].key = aws_sigv4_string((unsigned char *)"x-amz-content");
  sigv4_params.headers[0].value = aws_sigv4_string((unsigned char *)"v");
  sigv4_params.num_headers = 1;

  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
  aws_sigv4_header_t auth_header = {
      .value = aws_sigv4_string((unsigned char *)auth_buf)};

  ck_assert_int_eq(aws_sigv4_sign(&sigv4_params, &auth_header), AWS_SIGV4_OK);
  ck_assert_ptr_nonnull(strstr(auth_buf, "SignedHeaders=host;x-amz-content;x-amz-content-sha256;x-amz-date,"));
  ck_assert_ptr_nonnull(strstr((char *)scratch.canonical_request, "x-amz-content-sha256:UNSIGNED-PAYLOAD\n"));
}
END_TEST

/* S3 subresources such as ?versions, ?acl or ?uploads carry no '=' and are signed as
   "key="; expected signature from botocore's S3SigV4Auth */
START_TEST(AwsSigv4Test_ValuelessQueryParamsAreSigned)
{
  aws_sigv4_params_t sigv4_params = valid_params;
  sigv4_params.query_str = aws_sigv4_string((unsigned char *)"versions&prefix=a&acl");

  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
  aws_sigv4_header_t auth_header = {
      .value = aws_sigv4_string((unsigned char *)auth_buf)};

  ck_assert_int_eq(aws_sigv4_sign(&sigv4_params, &auth_header), AWS_SIGV4_OK);
  ck_assert_ptr_nonnull(strstr((char *)scratch.canonical_request, "\nacl=&prefix=a&versions=\n"));
  ck_assert_pstr_eq(auth_buf, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260803/eu-central-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=5fcca9d3eff90f36048028aabc1e14c281bf88854dea446a542712dc8981965d");
}
END_TEST

/* an empty header value is still a "name:\n" line; expected signature from botocore */
START_TEST(AwsSigv4Test_EmptyHeaderValueIsSigned)
{
  aws_sigv4_params_t sigv4_params = valid_params;
  sigv4_params.method = aws_sigv4_string((unsigned char *)"PUT");
  sigv4_params.uri = aws_sigv4_string((unsigned char *)"/obj.txt");
  sigv4_params.headers[0].key = aws_sigv4_string((unsigned char *)"x-amz-meta-empty");
  sigv4_params.headers[0].value = aws_sigv4_string((unsigned char *)"");
  sigv4_params.num_headers = 1;

  char auth_buf[AWS_SIGV4_AUTH_HEADER_MAX_LEN] = {0};
  aws_sigv4_header_t auth_header = {
      .value = aws_sigv4_string((unsigned char *)auth_buf)};

  ck_assert_int_eq(aws_sigv4_sign(&sigv4_params, &auth_header), AWS_SIGV4_OK);
  ck_assert_ptr_nonnull(strstr((char *)scratch.canonical_request, "\nx-amz-meta-empty:\n\n"));
  ck_assert_pstr_eq(auth_buf, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260803/eu-central-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-empty, Signature=da67b15c172a1febe40bdabcb3e1b1cd4a0a797aa8280726895197a78263d96e");
}
END_TEST

Suite *aws_sigv4_test_suite(void)
{
  Suite *s;
  s = suite_create("AwsSigv4Test");

  TCase *tc_aws_sigv4_sign = tcase_create("AwsSigv4Test_AwsSigv4Sign");
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_AwsSigv4Sign);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_AdditionalHeadersAreSigned);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_PrefixHeaderNamesAreOrdered);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_TooLargeCanonicalRequestFails);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_TooLongSigningKeyPartsFail);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_MissingScratchIsRejected);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_TooManyQueryParamsFails);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_TooManyHeadersRejected);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_BadHmacRejected);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_SnprintfStaysWithinN);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_ExportedBuildersStayBeforeLast);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_ContentSha256PrefixIsNotTheHeader);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_ValuelessQueryParamsAreSigned);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_EmptyHeaderValueIsSigned);
  suite_add_tcase(s, tc_aws_sigv4_sign);
  return s;
}

int main(int argc, char **argv)
{
  int number_failed;
  SRunner *sr;

  sr = srunner_create(aws_sigv4_test_suite());

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}