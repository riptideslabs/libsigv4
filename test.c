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

Suite *aws_sigv4_test_suite(void)
{
  Suite *s;
  s = suite_create("AwsSigv4Test");

  TCase *tc_aws_sigv4_sign = tcase_create("AwsSigv4Test_AwsSigv4Sign");
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_AwsSigv4Sign);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_AdditionalHeadersAreSigned);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_PrefixHeaderNamesAreOrdered);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_TooLargeCanonicalRequestFails);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_MissingScratchIsRejected);
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_TooManyQueryParamsFails);
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