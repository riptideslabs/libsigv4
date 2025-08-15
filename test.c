#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <check.h>

#include "sigv4.h"

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

Suite *aws_sigv4_test_suite(void)
{
  Suite *s;
  s = suite_create("AwsSigv4Test");

  TCase *tc_aws_sigv4_sign = tcase_create("AwsSigv4Test_AwsSigv4Sign");
  tcase_add_test(tc_aws_sigv4_sign, AwsSigv4Test_AwsSigv4Sign);
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