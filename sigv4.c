#include "sigv4.h"

#define AWS_SIGV4_AUTH_HEADER_NAME "Authorization"
#define AWS_SIGV4_SIGNING_ALGORITHM "AWS4-HMAC-SHA256"
#define SHA256_DIGEST_SIZE 32
#define AWS_SIGV4_HEX_SHA256_LENGTH SHA256_DIGEST_SIZE * 2
#define AWS_SIGV4_CANONICAL_REQUEST_BUF_LEN 2048 // Increased for large session tokens
#define AWS_SIGV4_STRING_TO_SIGN_BUF_LEN 2048    // Increased for large session tokens
#define AWS_SIGV4_KEY_BUF_LEN 64
#define AWS_SIGV4_MAX_NUM_QUERY_COMPONENTS 50
#define HMAC_MAX_MD_CBLOCK 128

int aws_sigv4_empty_str(aws_sigv4_str_t *str)
{
  return (str == NULL || str->data == NULL || str->len == 0) ? 1 : 0;
}

aws_sigv4_str_t aws_sigv4_string(const unsigned char *cstr)
{
  aws_sigv4_str_t ret = {.data = NULL};
  if (cstr)
  {
    ret.data = (unsigned char *)cstr;
    ret.len = strlen((char *)cstr);
  }
  return ret;
}

int aws_sigv4_strcmp(aws_sigv4_str_t *str1, aws_sigv4_str_t *str2)
{
  size_t len = str1->len <= str2->len ? str1->len : str2->len;
  return strncmp((char *)str1->data, (char *)str2->data, len);
}

/* reference: http://lxr.nginx.org/source/src/core/ngx_string.c */
static unsigned char *aws_sigv4_vslprintf(unsigned char *buf, unsigned char *last,
                                          const char *fmt, va_list args)
{
  unsigned char *c_ptr = buf;
  aws_sigv4_str_t *str;

  while (*fmt && c_ptr < last)
  {
    size_t n_max = last - c_ptr;
    if (*fmt == '%')
    {
      if (*(fmt + 1) == 'V')
      {
        str = va_arg(args, aws_sigv4_str_t *);
        if (aws_sigv4_empty_str(str))
        {
          goto finished;
        }
        size_t cp_len = n_max >= str->len ? str->len : n_max;
        strncpy((char *)c_ptr, (char *)str->data, cp_len);
        c_ptr += cp_len;
        fmt += 2;
      }
      else
      {
        *(c_ptr++) = *(fmt++);
      }
    }
    else
    {
      *(c_ptr++) = *(fmt++);
    }
  }
  *c_ptr = '\0';
finished:
  return c_ptr;
}

unsigned char *aws_sigv4_sprintf(unsigned char *buf, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  unsigned char *dst = aws_sigv4_vslprintf(buf, (void *)-1, fmt, args);
  va_end(args);
  return dst;
}

unsigned char *aws_sigv4_snprintf(unsigned char *buf, unsigned int n, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  unsigned char *dst = aws_sigv4_vslprintf(buf, buf + n, fmt, args);
  va_end(args);
  return dst;
}

static bool is_s3(aws_sigv4_params_t *sigv4_params)
{
  return sigv4_params->service.data &&
         sigv4_params->service.len >= 2 &&
         strncmp((char *)sigv4_params->service.data, "s3", 2) == 0;
}

static int aws_sigv4_kv_cmp(aws_sigv4_kv_t *p1,
                            aws_sigv4_kv_t *p2)
{
  size_t len = p1->key.len <= p2->key.len ? p1->key.len : p2->key.len;
  return strncmp((char *)p1->key.data, (char *)p2->key.data, len);
}

static int aws_sigv4_str_cmp(aws_sigv4_str_t *p1,
                             aws_sigv4_str_t *p2)
{
  size_t len = p1->len <= p2->len ? p1->len : p2->len;
  return strncmp((char *)p1->data, (char *)p2->data, len);
}

static unsigned char *construct_query_str(unsigned char *dst_cstr,
                                          aws_sigv4_kv_t *query_params,
                                          size_t query_num)
{
  size_t i;
  for (i = 0; i < query_num; i++)
  {
    /* here we assume args are percent-encoded */
    dst_cstr = aws_sigv4_sprintf(dst_cstr, "%V=%V",
                                 &query_params[i].key, &query_params[i].value);
    if (i != query_num - 1)
    {
      *(dst_cstr++) = '&';
    }
  }
  return dst_cstr;
}

static void parse_query_params(aws_sigv4_str_t *query_str,
                               aws_sigv4_kv_t *query_params,
                               size_t *arr_len)
{
  if (aws_sigv4_empty_str(query_str) || query_params == NULL)
  {
    arr_len = 0;
    return;
  }
  size_t idx = 0;
  unsigned char *c_ptr = query_str->data;
  query_params[0].key.data = c_ptr;
  /* here we assume query string are well-formed */
  while (c_ptr != query_str->data + query_str->len)
  {
    if (*c_ptr == '=')
    {
      query_params[idx].key.len = c_ptr - query_params[idx].key.data;
      query_params[idx].value.data = ++c_ptr;
    }
    else if (*c_ptr == '&')
    {
      query_params[idx].value.len = c_ptr - query_params[idx].value.data;
      query_params[++idx].key.data = ++c_ptr;
    }
    else
    {
      c_ptr++;
    }
  }
  query_params[idx].value.len = c_ptr - query_params[idx].value.data;
  *arr_len = idx + 1;
}

void get_hexdigest(aws_sigv4_str_t *str_in, aws_sigv4_str_t *hex_out)
{
  static const unsigned char digits[] = "0123456789abcdef";
  unsigned char *c_ptr = hex_out->data;
  size_t i;
  for (i = 0; i < str_in->len; i++)
  {
    *(c_ptr++) = digits[(str_in->data[i] & 0xf0) >> 4];
    *(c_ptr++) = digits[str_in->data[i] & 0x0f];
  }
  hex_out->len = str_in->len * 2;
}

void get_hex_sha256(aws_sigv4_params_t *sigv4_params, aws_sigv4_str_t *str_in, aws_sigv4_str_t *hex_sha256_out)
{
  unsigned char sha256_buf[SHA256_DIGEST_SIZE];
  sigv4_params->sha256(str_in->data, str_in->len, sha256_buf);

  aws_sigv4_str_t sha256_str = {.data = sha256_buf, .len = SHA256_DIGEST_SIZE};
  get_hexdigest(&sha256_str, hex_sha256_out);
}

void get_signing_key(aws_sigv4_params_t *sigv4_params, aws_sigv4_str_t *signing_key)
{
  unsigned char key_buf[AWS_SIGV4_KEY_BUF_LEN] = {0};
  unsigned char msg_buf[AWS_SIGV4_KEY_BUF_LEN] = {0};
  aws_sigv4_str_t key = {.data = key_buf};
  aws_sigv4_str_t msg = {.data = msg_buf};
  /* kDate = HMAC("AWS4" + kSecret, Date) */
  key.len = aws_sigv4_sprintf(key_buf, "AWS4%V", &sigv4_params->secret_access_key) - key_buf;
  /* data in YYYYMMDD format */
  msg.len = aws_sigv4_snprintf(msg_buf, 8, "%V", &sigv4_params->x_amz_date) - msg_buf;
  /* get HMAC SHA256 */
  sigv4_params->hmac_sha256(msg.data, msg.len, key.data, key.len,
                            signing_key->data, (size_t *)&signing_key->len);
  /* kRegion = HMAC(kDate, Region) */
  memcpy(key_buf, signing_key->data, signing_key->len);
  key.len = signing_key->len;
  msg.len = aws_sigv4_sprintf(msg_buf, "%V", &sigv4_params->region) - msg_buf;
  sigv4_params->hmac_sha256(msg.data, msg.len, key.data, key.len,
                            signing_key->data, (size_t *)&signing_key->len);
  /* kService = HMAC(kRegion, Service) */
  memcpy(key_buf, signing_key->data, signing_key->len);
  key.len = signing_key->len;
  msg.len = aws_sigv4_sprintf(msg_buf, "%V", &sigv4_params->service) - msg_buf;
  sigv4_params->hmac_sha256(msg.data, msg.len, key.data, key.len,
                            signing_key->data, (size_t *)&signing_key->len);
  /* kSigning = HMAC(kService, "aws4_request") */
  memcpy(key_buf, signing_key->data, signing_key->len);
  key.len = signing_key->len;
  msg.len = aws_sigv4_sprintf(msg_buf, "aws4_request") - msg_buf;
  sigv4_params->hmac_sha256(msg.data, msg.len, key.data, key.len,
                            signing_key->data, (size_t *)&signing_key->len);
}

void get_credential_scope(aws_sigv4_params_t *sigv4_params,
                          aws_sigv4_str_t *credential_scope)
{
  unsigned char *str = credential_scope->data;
  /* get date in yyyymmdd format */
  str = aws_sigv4_snprintf(str, 8, "%V", &sigv4_params->x_amz_date);
  str = aws_sigv4_sprintf(str, "/%V/%V/aws4_request",
                          &sigv4_params->region, &sigv4_params->service);
  credential_scope->len = str - credential_scope->data;
}

void get_signed_headers(aws_sigv4_params_t *sigv4_params,
                        aws_sigv4_str_t *signed_headers)
{
  aws_sigv4_str_t headers[AWS_SIGV4_MAX_NUM_HEADERS];
  unsigned num_headers = 0;
  bool has_amz_content_sha256_header = false;

  // copy additional headers from sigv4_params
  size_t i;
  for (i = 0; i < sigv4_params->num_headers && num_headers < AWS_SIGV4_MAX_NUM_HEADERS; i++)
  {
    // check if the header is x-amz-content-sha256
    if (strncasecmp(sigv4_params->headers[i].key.data, "x-amz-content-sha256", sigv4_params->headers[i].key.len) == 0)
    {
      has_amz_content_sha256_header = true;
    }
    headers[num_headers++] = sigv4_params->headers[i].key;
  }

  // add host and x-amz-date headers to additional headers, and x-amz-content-sha256 if s3, and header not present
  headers[num_headers++] = aws_sigv4_string("host");
  headers[num_headers++] = aws_sigv4_string("x-amz-date");
  if (is_s3(sigv4_params) && !has_amz_content_sha256_header)
  {
    headers[num_headers++] = aws_sigv4_string("x-amz-content-sha256");
  }

  // sort additional headers
  sigv4_params->sort(headers, num_headers, sizeof(aws_sigv4_str_t), (aws_sigv4_compare_func_t)aws_sigv4_str_cmp);

  // construct signed headers string
  unsigned char *str = signed_headers->data;
  for (i = 0; i < num_headers; i++)
  {
    if (i > 0)
    {
      str = aws_sigv4_sprintf(str, ";");
    }
    str = aws_sigv4_sprintf(str, "%V", &headers[i]);
  }

  signed_headers->len = str - signed_headers->data;
}

void get_canonical_headers(aws_sigv4_params_t *sigv4_params,
                           aws_sigv4_str_t *canonical_headers)
{
  aws_sigv4_kv_t headers[AWS_SIGV4_MAX_NUM_HEADERS];
  unsigned num_headers = 0;
  aws_sigv4_kv_t *amz_content_sha256_header = NULL;

  // calculate the SHA256 hash of the payload, might be needed for S3
  unsigned char content_sha256_buf[AWS_SIGV4_HEX_SHA256_LENGTH + 1] = {0}; // +1 for null terminator
  aws_sigv4_str_t content_sha256 = {.data = content_sha256_buf};

  // copy additional headers from sigv4_params
  size_t i;
  for (i = 0; i < sigv4_params->num_headers && num_headers < AWS_SIGV4_MAX_NUM_HEADERS; i++)
  {
    // check if the header is x-amz-content-sha256
    if (strncasecmp(sigv4_params->headers[i].key.data, "x-amz-content-sha256", sigv4_params->headers[i].key.len) == 0)
    {
      amz_content_sha256_header = &sigv4_params->headers[i];
    }
    // TODO: Should also trim and normalize header values according to AWS spec
    // For now, just copy the value as-is
    headers[num_headers++] = sigv4_params->headers[i];
  }

  // add host and x-amz-date headers to additional headers, and x-amz-content-sha256 if s3
  headers[num_headers++] = (aws_sigv4_kv_t){.key = aws_sigv4_string("host"), .value = sigv4_params->host};
  headers[num_headers++] = (aws_sigv4_kv_t){.key = aws_sigv4_string("x-amz-date"), .value = sigv4_params->x_amz_date};
  if (is_s3(sigv4_params) && !amz_content_sha256_header)
  {
    aws_sigv4_kv_t content_sha256_kv;
    if (!sigv4_params->unsigned_payload)
    {
      get_hex_sha256(sigv4_params, &sigv4_params->payload, &content_sha256);
    }
    content_sha256_kv = (aws_sigv4_kv_t){
        .key = aws_sigv4_string("x-amz-content-sha256"),
        .value = sigv4_params->unsigned_payload ? aws_sigv4_string("UNSIGNED-PAYLOAD") : content_sha256,
    };
    headers[num_headers++] = content_sha256_kv;
  }

  // sort additional headers
  sigv4_params->sort(headers, num_headers, sizeof(aws_sigv4_kv_t), (aws_sigv4_compare_func_t)aws_sigv4_kv_cmp);

  // construct canonical headers string
  unsigned char *str = canonical_headers->data;
  for (i = 0; i < num_headers; i++)
  {
    str = aws_sigv4_sprintf(str, "%V:%V\n", &headers[i].key, &headers[i].value);
  }

  canonical_headers->len = str - canonical_headers->data;
}

int get_canonical_request(aws_sigv4_params_t *sigv4_params,
                          aws_sigv4_str_t *canonical_request)
{
  unsigned char *str = canonical_request->data;
  /* TODO: Here we assume the URI and query string have already been encoded.
   *       Add encoding logic in future.
   */
  str = aws_sigv4_sprintf(str, "%V\n%V\n",
                          &sigv4_params->method,
                          &sigv4_params->uri);

  /* query string can be empty */
  if (!aws_sigv4_empty_str(&sigv4_params->query_str))
  {
    aws_sigv4_kv_t query_params[AWS_SIGV4_MAX_NUM_QUERY_COMPONENTS];
    size_t query_num = 0;
    parse_query_params(&sigv4_params->query_str, query_params, &query_num);
    sigv4_params->sort(query_params, query_num, sizeof(aws_sigv4_kv_t),
                       (aws_sigv4_compare_func_t)aws_sigv4_kv_cmp);
    str = construct_query_str(str, query_params, query_num);
  }
  *(str++) = '\n';

  aws_sigv4_str_t canonical_headers = {.data = str};
  get_canonical_headers(sigv4_params, &canonical_headers);
  str += canonical_headers.len;
  *(str++) = '\n';

  aws_sigv4_str_t signed_headers = {.data = str};
  get_signed_headers(sigv4_params, &signed_headers);
  str += signed_headers.len;
  *(str++) = '\n';

  // Use UNSIGNED-PAYLOAD if specified, otherwise compute payload hash
  if (sigv4_params->unsigned_payload && is_s3(sigv4_params))
  {
    str = aws_sigv4_sprintf(str, "UNSIGNED-PAYLOAD");
  }
  else
  {
    aws_sigv4_str_t hex_sha256 = {.data = str};
    get_hex_sha256(sigv4_params, &sigv4_params->payload, &hex_sha256);
    str += hex_sha256.len;
  }

  canonical_request->len = str - canonical_request->data;

  // Check for buffer overflow
  if (canonical_request->len >= AWS_SIGV4_CANONICAL_REQUEST_BUF_LEN)
  {
    return AWS_SIGV4_BUFFER_OVERFLOW_ERROR;
  }
  return AWS_SIGV4_OK;
}

void get_string_to_sign(aws_sigv4_params_t *sigv4_params,
                        aws_sigv4_str_t *request_date,
                        aws_sigv4_str_t *credential_scope,
                        aws_sigv4_str_t *canonical_request,
                        aws_sigv4_str_t *string_to_sign)
{
  unsigned char *str = string_to_sign->data;
  str = aws_sigv4_sprintf(str, "AWS4-HMAC-SHA256\n%V\n%V\n",
                          request_date, credential_scope);

  aws_sigv4_str_t hex_sha256 = {.data = str};
  get_hex_sha256(sigv4_params, canonical_request, &hex_sha256);
  str += hex_sha256.len;

  string_to_sign->len = str - string_to_sign->data;
}

int aws_sigv4_sign(aws_sigv4_params_t *sigv4_params, aws_sigv4_header_t *auth_header)
{
  int rc = AWS_SIGV4_OK;
  if (auth_header == NULL || sigv4_params == NULL || aws_sigv4_empty_str(&sigv4_params->secret_access_key) || aws_sigv4_empty_str(&sigv4_params->access_key_id) || aws_sigv4_empty_str(&sigv4_params->method) || aws_sigv4_empty_str(&sigv4_params->uri) || aws_sigv4_empty_str(&sigv4_params->host) || aws_sigv4_empty_str(&sigv4_params->x_amz_date) || aws_sigv4_empty_str(&sigv4_params->region) || aws_sigv4_empty_str(&sigv4_params->service) || sigv4_params->sort == NULL || sigv4_params->sha256 == NULL || sigv4_params->hmac_sha256 == NULL)
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto err;
  }

  // Normalize additional header names to lowercase at the beginning
  size_t i;
  for (i = 0; i < sigv4_params->num_headers; i++)
  {
    size_t j;
    for (j = 0; j < sigv4_params->headers[i].key.len; j++)
    {
      if (isupper(sigv4_params->headers[i].key.data[j]))
      {
        sigv4_params->headers[i].key.data[j] = tolower(sigv4_params->headers[i].key.data[j]);
      }
    }
  }

  auth_header->key.data = (unsigned char *)AWS_SIGV4_AUTH_HEADER_NAME;
  auth_header->key.len = strlen(AWS_SIGV4_AUTH_HEADER_NAME);

  /* AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/<credential_scope> */
  unsigned char *str = auth_header->value.data;
  str = aws_sigv4_sprintf(str, "AWS4-HMAC-SHA256 Credential=%V/",
                          &sigv4_params->access_key_id);

  aws_sigv4_str_t credential_scope = {.data = str};
  get_credential_scope(sigv4_params, &credential_scope);
  str += credential_scope.len;

  /* SignedHeaders=<signed_headers> */
  str = aws_sigv4_sprintf(str, ", SignedHeaders=");
  aws_sigv4_str_t signed_headers = {.data = str};
  get_signed_headers(sigv4_params, &signed_headers);
  str += signed_headers.len;

  /* Signature=<signature> */
  str = aws_sigv4_sprintf(str, ", Signature=");
  /* Task 1: Create a canonical request */
  unsigned char canonical_request_buf[AWS_SIGV4_CANONICAL_REQUEST_BUF_LEN] = {0};
  aws_sigv4_str_t canonical_request = {.data = canonical_request_buf};
  get_canonical_request(sigv4_params, &canonical_request);
  /* Task 2: Create a string to sign */
  unsigned char string_to_sign_buf[AWS_SIGV4_STRING_TO_SIGN_BUF_LEN] = {0};
  aws_sigv4_str_t string_to_sign = {.data = string_to_sign_buf};
  get_string_to_sign(sigv4_params, &sigv4_params->x_amz_date, &credential_scope,
                     &canonical_request, &string_to_sign);
  /* Task 3: Calculate the signature */
  /* 3.1: Derive signing key */
  unsigned char signing_key_buf[AWS_SIGV4_KEY_BUF_LEN] = {0};
  aws_sigv4_str_t signing_key = {.data = signing_key_buf};
  get_signing_key(sigv4_params, &signing_key);
  /* 3.2: Calculate signature on the string to sign */
  unsigned char signed_msg_buf[HMAC_MAX_MD_CBLOCK] = {0};
  aws_sigv4_str_t signed_msg = {.data = signed_msg_buf};
  /* get HMAC SHA256 */
  sigv4_params->hmac_sha256(
      string_to_sign.data, string_to_sign.len,
      signing_key.data, signing_key.len,
      signed_msg.data, (size_t *)&signed_msg.len);
  aws_sigv4_str_t signature = {.data = str};
  get_hexdigest(&signed_msg, &signature);
  str += signature.len;
  auth_header->value.len = str - auth_header->value.data;

  // Check for auth header buffer overflow
  if (auth_header->value.len >= AWS_SIGV4_AUTH_HEADER_MAX_LEN)
  {
    rc = AWS_SIGV4_BUFFER_OVERFLOW_ERROR;
    goto err;
  }

err:
  return rc;
}
