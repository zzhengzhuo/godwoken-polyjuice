
#ifndef ASSERT
#define ASSERT(s) (void)0
#endif

#include <stdbool.h>
#include <string.h>
#include <ckb_consts.h>

#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/rsa.h"

#if defined(CKB_USE_SIM)
#include <stdio.h>
#define mbedtls_printf printf
#else
#define mbedtls_printf(x, ...) (void)0
#endif


// used as algorithm_id, see below
// when algorithm_id is CKB_VERIFY_RSA, use RsaInfo structure
#define CKB_VERIFY_RSA 1
// when algorithm_id is CKB_VERIFY_ISO9796_2, use RsaInfo structure
#define CKB_VERIFY_ISO9796_2 2

// used as key_size enum values: their "KeySize" are 1024, 2048, 4098 bits.
// The term "KeySize" has same meaning below.
#define CKB_KEYSIZE_1024 1
#define CKB_KEYSIZE_2048 2
#define CKB_KEYSIZE_4096 3

// used as padding value
// PKCS# 1.5
#define CKB_PKCS_15 0
// PKCS# 2.1
#define CKB_PKCS_21 1

// used as md_type value (message digest), it has same value as
// mbedtls_md_type_t
#define CKB_MD_NONE 0
// very weak hash function
//#define CKB_MD_MD2 1       /**< The MD2 message digest. */
//#define CKB_MD_MD4 2       /**< The MD4 message digest. */
//#define CKB_MD_MD5 3       /**< The MD5 message digest. */
// SHA1 is weak too, but it's already used by ISO 9796-2
// It's not allowed to set SHA1 while using RSA
#define CKB_MD_SHA1 4   /**< The SHA-1 message digest. */
#define CKB_MD_SHA224 5 /**< The SHA-224 message digest. */
#define CKB_MD_SHA256 6 /**< The SHA-256 message digest. */
#define CKB_MD_SHA384 7 /**< The SHA-384 message digest. */
#define CKB_MD_SHA512 8 /**< The SHA-512 message digest. */
// #define CKB_MD_RIPEMD160 9 /**< The RIPEMD-160 message digest. */

#define PLACEHOLDER_SIZE (128)

/** signature (in witness, or passed as arguments) memory layout
 * This structure contains the following information:
 * 1) Common header, 4 bytes, see RsaInfo
 * 2) RSA Public Key
 * 3) RSA Signature data
 *
-----------------------------------------------------------------------------
|common header| E |  N (KeySize/8 bytes) | RSA Signature (KeySize/8 bytes)|
-----------------------------------------------------------------------------
The common header, E both occupy 4 bytes. E is in little endian(uint32_t).
So the total length in byte is: 4 + 4 + KeySize/8 + KeySize/8.

The public key hash is calculated by: blake160(common header + E + N), Note: RSA
signature part is dropped. Here function blake160 returns the first 20 bytes of
blake2b result.
*/
typedef struct RsaInfo {
  // common header part, 4 bytes
  // if it doesn't take 4 bytes in memory, ERROR_BAD_MEMORY_LAYOUT returned
  // from validate_signature
  uint8_t algorithm_id;
  uint8_t key_size;
  uint8_t padding;
  uint8_t md_type;

  // RSA public key, part E. It's normally very small, OK to use uint32_to hold
  // it. https://eprint.iacr.org/2008/510.pdf The choice e = 65537 = 2^16 + 1 is
  // especially widespread. Of the certificates observed in the UCSD TLS Corpus
  // [23] (which was obtained by surveying frequently-used TLS servers), 99.5%
  // had e = 65537, and all had e at most 32 bits.
  uint32_t E;

  // The following parts are with variable length. We give it a placeholder.
  // The real length are both KeySize/8.

  // RSA public key, part N.
  // The public key is the combination of E and N.
  // But N is a very large number and need to use array to represent it.
  // The total length in byte is (KeySize)/8.
  // The memory layout is the same as the field "p" of mbedtls_mpi type.
  uint8_t N[PLACEHOLDER_SIZE];

  // pointer to RSA signature
  uint8_t sig[PLACEHOLDER_SIZE];
} RsaInfo;

enum ErrorCode {
  // 0 is the only success code. We can use 0 directly.
  // error code is starting from 40, to avoid conflict with
  // common error code in other scripts.
  ERROR_RSA_INVALID_PARAM1 = 40,
  ERROR_RSA_INVALID_PARAM2,
  ERROR_RSA_VERIFY_FAILED,
  ERROR_RSA_ONLY_INIT,
  ERROR_RSA_INVALID_KEY_SIZE,
  ERROR_RSA_INVALID_MD_TYPE2,
  ERROR_RSA_INVALID_ID,
  ERROR_BAD_MEMORY_LAYOUT,
  ERROR_INVALID_MD_TYPE,
  ERROR_INVALID_PADDING,
  ERROR_MD_FAILED,
  ERROR_MBEDTLS_ERROR_1,
  ERROR_ISO97962_MISMATCH_HASH,
  ERROR_ISO97962_INVALID_ARG1,
  ERROR_ISO97962_INVALID_ARG2,
  ERROR_ISO97962_INVALID_ARG3,
  ERROR_ISO97962_INVALID_ARG4,
  ERROR_ISO97962_INVALID_ARG5,
  ERROR_ISO97962_INVALID_ARG6,
  ERROR_ISO97962_INVALID_ARG7,
  ERROR_ISO97962_INVALID_ARG8,
  ERROR_ISO97962_INVALID_ARG9,
  ERROR_ISO97962_INVALID_ARG10,
  ERROR_ISO97962_INVALID_ARG11,
  ERROR_ISO97962_INVALID_ARG12,
  ERROR_ISO97962_INVALID_ARG13,
  ERROR_WRONG_PUBKEY,
};

#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      ASSERT(0);           \
      goto exit;           \
    }                      \
  } while (0)

#define CHECK3(code)  \
  do {               \
    if (code != 0) { \
      err = code;    \
      ASSERT(0);     \
      goto exit;     \
    }                \
  } while (0)

int md_string(const mbedtls_md_info_t *md_info, const uint8_t *buf, size_t n,
              unsigned char *output);

// remove SHA1 and RIPEMD160 as options for the message digest hash functions.
bool is_valid_rsa_md_type(uint8_t md) {
  return md == CKB_MD_SHA224 || md == CKB_MD_SHA256 || md == CKB_MD_SHA384 ||
         md == CKB_MD_SHA512;
}

bool is_valid_key_size(uint8_t size) {
  return size == CKB_KEYSIZE_1024 || size == CKB_KEYSIZE_2048 ||
         size == CKB_KEYSIZE_4096;
}

bool is_valid_key_size_in_bit(uint32_t size) {
  return size == 1024 || size == 2048 || size == 4096;
}

bool is_valid_padding(uint8_t padding) {
  return padding == CKB_PKCS_15 || padding == CKB_PKCS_21;
}

uint32_t get_key_size(uint8_t key_size_enum) {
  if (key_size_enum == CKB_KEYSIZE_1024) {
    return 1024;
  } else if (key_size_enum == CKB_KEYSIZE_2048) {
    return 2048;
  } else if (key_size_enum == CKB_KEYSIZE_4096) {
    return 4096;
  } else {
    ASSERT(false);
    return 0;
  }
}

int check_pubkey(mbedtls_mpi *N, mbedtls_mpi *E) {
  int err = 0;
  size_t key_size = mbedtls_mpi_size(N) * 8;
  CHECK2(is_valid_key_size_in_bit(key_size), ERROR_WRONG_PUBKEY);

  mbedtls_mpi two;
  mbedtls_mpi_init(&two);
  err = mbedtls_mpi_lset(&two, 2);
  CHECK3(err);
  CHECK2(mbedtls_mpi_cmp_mpi(&two, E) < 0 && mbedtls_mpi_cmp_mpi(E, N) < 0,
         ERROR_WRONG_PUBKEY);

  err = 0;
exit:
  return err;
}

mbedtls_md_type_t convert_md_type(uint8_t type) {
  mbedtls_md_type_t result = MBEDTLS_MD_NONE;
  switch (type) {
    case CKB_MD_SHA224:
      result = MBEDTLS_MD_SHA224;
      break;
    case CKB_MD_SHA256:
      result = MBEDTLS_MD_SHA256;
      break;
    case CKB_MD_SHA384:
      result = MBEDTLS_MD_SHA384;
      break;
    case CKB_MD_SHA512:
      result = MBEDTLS_MD_SHA512;
      break;
    case CKB_MD_SHA1:
      result = MBEDTLS_MD_SHA1;
      break;
    default:
      ASSERT(0);
      result = MBEDTLS_MD_NONE;
  }
  return result;
}

int convert_padding(uint8_t padding) {
  if (padding == CKB_PKCS_15) {
    return MBEDTLS_RSA_PKCS_V15;
  } else if (padding == CKB_PKCS_21) {
    return MBEDTLS_RSA_PKCS_V21;
  } else {
    ASSERT(0);
  }
  return -1;
}

int load_prefilled_data(void *data,
                                                               size_t *len) {
  (void)data;
  *len = 0;
  return CKB_SUCCESS;
}

uint8_t *get_rsa_signature(RsaInfo *info) {
  int length = get_key_size(info->key_size) / 8;
  // note: sanitizer reports error:
  // Index 256 out of bounds for type 'uint8_t [128]'
  // It's intended. RsaInfo is actually an variable length buffer.
  return (uint8_t *)&info->N[length];
}

uint32_t calculate_rsa_info_length(int key_size) { return 8 + key_size / 4; }

int validate_signature_rsa(void *prefilled_data,
                           const uint8_t *signature_buffer,
                           uint32_t signature_size, const uint8_t *msg_buf,
                           uint32_t msg_size, uint8_t *output,
                           uint32_t *output_len) {
  (void)prefilled_data;
  (void)output;
  (void)output_len;
  int err = ERROR_RSA_ONLY_INIT;
  uint8_t hash_buf[MBEDTLS_MD_MAX_SIZE] = {0};
  uint32_t hash_size = 0;
  uint32_t key_size = 0;
  bool is_rsa_inited = false;
  mbedtls_rsa_context rsa;

  RsaInfo *input_info = (RsaInfo *)signature_buffer;

  // for key size with 1024 and 2048 bits, it uses up to 7K bytes.
  int alloc_buff_size = 1024 * 7;
  // for key size with 4096 bits, it uses 12K bytes at most.
  if (input_info->key_size == CKB_KEYSIZE_4096) alloc_buff_size = 1024 * 12;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  CHECK2(is_valid_rsa_md_type(input_info->md_type), ERROR_INVALID_MD_TYPE);
  CHECK2(is_valid_padding(input_info->padding), ERROR_INVALID_PADDING);
  CHECK2(is_valid_key_size(input_info->key_size), ERROR_RSA_INVALID_KEY_SIZE);
  key_size = get_key_size(input_info->key_size);
  CHECK2(key_size > 0, ERROR_RSA_INVALID_KEY_SIZE);
  CHECK2(signature_buffer != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK2(msg_buf != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK2(signature_size == (size_t)calculate_rsa_info_length(key_size),
         ERROR_RSA_INVALID_PARAM2);

  mbedtls_md_type_t md_type;
  md_type = convert_md_type(input_info->md_type);
  const mbedtls_md_info_t *md_info;
  md_info = mbedtls_md_info_from_type(md_type);
  CHECK2(md_info != NULL, ERROR_RSA_INVALID_MD_TYPE2);

  hash_size = md_info->size;
  int padding;
  padding = convert_padding(input_info->padding);

  is_rsa_inited = true;
  mbedtls_rsa_init(&rsa, padding, 0);

  err = mbedtls_mpi_read_binary_le(
      &rsa.E, (const unsigned char *)&input_info->E, sizeof(uint32_t));
  CHECK2(err == 0, ERROR_MBEDTLS_ERROR_1);

  err = mbedtls_mpi_read_binary_le(&rsa.N, input_info->N, key_size / 8);
  CHECK2(err == 0, ERROR_MBEDTLS_ERROR_1);

  CHECK3(check_pubkey(&rsa.N, &rsa.E));

  rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;
  CHECK2(is_valid_key_size_in_bit(rsa.len * 8), ERROR_WRONG_PUBKEY);

  err = md_string(md_info, msg_buf, msg_size, hash_buf);
  CHECK2(err == 0, ERROR_MD_FAILED);
  err = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, md_type,
                                 hash_size, hash_buf,
                                 get_rsa_signature(input_info));
  if (err != 0) {
    debug_print_int("verify error",err);
    err = ERROR_RSA_VERIFY_FAILED;
    goto exit;
  }

  err = CKB_SUCCESS;

exit:
  if (is_rsa_inited) mbedtls_rsa_free(&rsa);
  return err;
}

/**
 * entry for different algorithms
 * The fist byte of signature_buffer is the algorithm_id, it can be:
 * #define CKB_VERIFY_RSA 1
 * #define CKB_VERIFY_ISO9796_2 2
s */
int validate_signature(
    void *prefilled_data, const uint8_t *sig_buf, uint32_t sig_len,
    const uint8_t *msg_buf, uint32_t msg_len, uint8_t *output,
    uint32_t *output_len) {
  // we have 4 bytes common header at the beginning of RsaInfo,
  // need to make sure they occupy exactly 4 bytes.
  if (sizeof(RsaInfo) != (PLACEHOLDER_SIZE * 2 + 8)) {
    ASSERT(0);
    return ERROR_BAD_MEMORY_LAYOUT;
  }
  if (sig_buf == NULL) {
    ASSERT(0);
    return ERROR_RSA_INVALID_PARAM1;
  }

  uint8_t id = ((RsaInfo *)sig_buf)->algorithm_id;

  if (id == CKB_VERIFY_RSA) {
    return validate_signature_rsa(prefilled_data, sig_buf, sig_len, msg_buf,
                                  msg_len, output, output_len);
  } else {
    return ERROR_RSA_INVALID_ID;
  }
}

int md_string(const mbedtls_md_info_t *md_info, const uint8_t *buf, size_t n,
              unsigned char *output) {
  int err = 0;
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);

  CHECK2(md_info != NULL, MBEDTLS_ERR_MD_BAD_INPUT_DATA);
  err = mbedtls_md_setup(&ctx, md_info, 0);
  CHECK3(err);
  err = mbedtls_md_starts(&ctx);
  CHECK3(err);
  err = mbedtls_md_update(&ctx, (const unsigned char *)buf, n);
  CHECK3(err);
  err = mbedtls_md_finish(&ctx, output);
  CHECK3(err);
  err = 0;
exit:
  mbedtls_md_free(&ctx);
  return err;
}