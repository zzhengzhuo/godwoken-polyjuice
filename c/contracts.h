#ifndef CONTRACTS_H_
#define CONTRACTS_H_

#include "mbedtls/bignum.h"
#include "ripemd160.h"
#include "sha256.h"
#include <intx/intx.hpp>
#include <bn128.hpp>

#include "polyjuice_utils.h"
#include "validate_signature_rsa.c"
#include "sudt_contracts.h"
#include "other_contracts.h"
#include "up_encrypt.h"

/* Protocol Params:
   [Referenced]:
   https://github.com/ethereum/go-ethereum/blob/master/params/protocol_params.go
*/
#define SHA256_BASE_GAS 60        // Base price for a SHA256 operation
#define SHA256_PERWORD_GAS 12     // Per-word price for a SHA256 operation
#define RIPEMD160_BASE_GAS 600    // Base price for a RIPEMD160 operation
#define RIPEMD160_PERWORD_GAS 120 // Per-word price for a RIPEMD160 operation
#define IDENTITY_BASE_GAS 15      // Base price for a data copy operation
#define IDENTITY_PERWORD_GAS 3    // Per-work price for a data copy operation

#define BN256_ADD_GAS_BYZANTIUM 500                // Byzantium gas needed for an elliptic curve addition
#define BN256_ADD_GAS_ISTANBUL 150                 // Gas needed for an elliptic curve addition
#define BN256_SCALAR_MUL_GAS_BYZANTIUM 40000       // Byzantium gas needed for an elliptic curve scalar multiplication
#define BN256_SCALAR_MUL_GAS_ISTANBUL 6000         // Gas needed for an elliptic curve scalar multiplication
#define BN256_PAIRING_BASE_GAS_BYZANTIUM 100000    // Byzantium base price for an elliptic curve pairing check
#define BN256_PAIRING_BASE_GAS_ISTANBUL 45000      // Base price for an elliptic curve pairing check
#define BN256_PAIRING_PERPOINT_GAS_BYZANTIUM 80000 // Byzantium per-point price for an elliptic curve pairing check
#define BN256_PAIRING_PERPOINT_GAS_ISTANBUL 34000  // Per-point price for an elliptic curve pairing check

#define BLAKE2F_INPUT_LENGTH 213
#define BLAKE2F_FINAL_BLOCK_BYTES 0x1
#define BLAKE2F_NON_FINAL_BLOCK_BYTES 0x0

/* pre-compiled Ethereum contracts */

typedef int (*precompiled_contract_gas_fn)(const uint8_t *input_src,
                                           const size_t input_size,
                                           uint64_t *gas);
typedef int (*precompiled_contract_fn)(gw_context_t *ctx,
                                       const uint8_t *code_data,
                                       const size_t code_size,
                                       bool is_static_call,
                                       const uint8_t *input_src,
                                       const size_t input_size,
                                       uint8_t **output, size_t *output_size);

int ecrecover_required_gas(const uint8_t *input, const size_t input_size,
                           uint64_t *gas)
{
  // Elliptic curve sender recovery gas price
  *gas = 3000;
  return 0;
}

/*
 * ecrecover() is a useful Solidity function.
 * It allows the smart contract to validate that incoming data is properly signed.
 * When input data is wrong we just return empty output with 0 return code.

  The input data: (hash, v, r, s), each 32 bytes
  ===============
    input[0 ..32]  => hash
    input[32..64]  => v (padded)
         [64]      => v
    input[64..128] => signature[0..64]
         [64..96 ] => r
         [96..128] => s
 */
int ecrecover(gw_context_t *ctx,
              const uint8_t *code_data,
              const size_t code_size,
              bool is_static_call,
              const uint8_t *input_src,
              const size_t input_size, uint8_t **output, size_t *output_size)
{
  int ret;
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
#ifdef GW_GENERATOR
  ret = ckb_secp256k1_custom_verify_only_initialize(ctx, &context, secp_data);
#else
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
#endif
  if (ret != 0)
  {
    return FATAL_PRECOMPILED_CONTRACTS;
  }

  uint8_t input[128] = {0};
  size_t real_size = input_size > 128 ? 128 : input_size;
  memcpy(input, input_src, real_size);
  for (int i = 32; i < 63; i++)
  {
    if (input[i] != 0)
    {
      ckb_debug("input[32:63] not all zero!");
      return 0;
    }
  }
  int recid = input[63] - 27;

  /* crypto.ValidateSignatureValues(v, r, s, false) */
  /* NOTE: r,s overflow will be checked in secp256k1 library code */
  if (recid != 0 && recid != 1)
  {
    ckb_debug("v value is not in {27,28}");
    return 0;
  }

  uint8_t signature_data[64];
  memcpy(signature_data, input + 64, 32);
  memcpy(signature_data + 32, input + 96, 32);
  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, signature_data, recid) == 0)
  {
    ckb_debug("parse signature failed");
    return 0;
  }
  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, input) != 1)
  {
    ckb_debug("recover public key failed");
    return 0;
  }

  /* Check pubkey hash */
  uint8_t temp[65];
  size_t pubkey_size = 65;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_UNCOMPRESSED) != 1)
  {
    ckb_debug("public key serialize failed");
    return FATAL_PRECOMPILED_CONTRACTS;
  }

  union ethash_hash256 hash_result = ethash::keccak256(temp + 1, 64);
  *output = (uint8_t *)malloc(32);
  if (*output == NULL)
  {
    return FATAL_PRECOMPILED_CONTRACTS;
  }
  memset(*output, 0, 12);
  memcpy(*output + 12, hash_result.bytes + 12, 20);
  *output_size = 32;
  return 0;
}

int sha256hash_required_gas(const uint8_t *input, const size_t input_size,
                            uint64_t *gas)
{
  *gas =
      (uint64_t)(input_size + 31) / 32 * SHA256_PERWORD_GAS + SHA256_BASE_GAS;
  return 0;
}

int sha256hash(gw_context_t *ctx,
               const uint8_t *code_data,
               const size_t code_size,
               bool is_static_call,
               const uint8_t *input_src,
               const size_t input_size, uint8_t **output, size_t *output_size)
{
  *output = (uint8_t *)malloc(32);
  if (*output == NULL)
  {
    return FATAL_PRECOMPILED_CONTRACTS;
  }
  *output_size = 32;
  SHA256_CTX hash_ctx;
  sha256_init(&hash_ctx);
  sha256_update(&hash_ctx, input_src, input_size);
  sha256_final(&hash_ctx, *output);
  return 0;
}

int ripemd160hash_required_gas(const uint8_t *input, const size_t input_size,
                               uint64_t *gas)
{
  *gas = (uint64_t)(input_size + 31) / 32 * RIPEMD160_PERWORD_GAS +
         RIPEMD160_BASE_GAS;
  return 0;
}

int ripemd160hash(gw_context_t *ctx,
                  const uint8_t *code_data,
                  const size_t code_size,
                  bool is_static_call,
                  const uint8_t *input_src,
                  const size_t input_size, uint8_t **output,
                  size_t *output_size)
{
  if (input_size > (size_t)UINT32_MAX)
  {
    /* input_size overflow */
    return FATAL_PRECOMPILED_CONTRACTS;
  }
  *output = (uint8_t *)malloc(32);
  if (*output == NULL)
  {
    return -1;
  }
  memset(*output, 0, 12);
  ripemd160(input_src, input_size, *output + 12);
  *output_size = 32;
  return 0;
}

int data_copy_required_gas(const uint8_t *input, const size_t input_size,
                           uint64_t *gas)
{
  *gas = (uint64_t)(input_size + 31) / 32 * IDENTITY_PERWORD_GAS +
         IDENTITY_BASE_GAS;
  return 0;
}

int data_copy(gw_context_t *ctx,
              const uint8_t *code_data,
              const size_t code_size,
              bool is_static_call,
              const uint8_t *input_src,
              const size_t input_size, uint8_t **output, size_t *output_size)
{
  *output = (uint8_t *)malloc(input_size);
  if (*output == NULL)
  {
    return FATAL_PRECOMPILED_CONTRACTS;
  }
  *output_size = input_size;
  memcpy(*output, input_src, input_size);
  return 0;
}

int read_lens(const uint8_t *input, const size_t input_size,
              mbedtls_mpi *base_len, mbedtls_mpi *exp_len, mbedtls_mpi *mod_len,
              size_t *base_size, size_t *exp_size, size_t *mod_size)
{
  int ret;

  uint8_t padded_input[96] = {0};
  size_t real_size = input_size > 96 ? 96 : input_size;
  memcpy(padded_input, input, real_size);

  mbedtls_mpi_init(base_len);
  mbedtls_mpi_init(exp_len);
  mbedtls_mpi_init(mod_len);
  ret = mbedtls_mpi_read_binary(base_len, padded_input, 32);
  if (ret != 0)
  {
    goto read_lens_error;
  }
  ret = mbedtls_mpi_read_binary(exp_len, padded_input + 32, 32);
  if (ret != 0)
  {
    goto read_lens_error;
  }
  ret = mbedtls_mpi_read_binary(mod_len, padded_input + 64, 32);
  if (ret != 0)
  {
    goto read_lens_error;
  }

  ret = mbedtls_mpi_write_binary_le(base_len, (unsigned char *)(base_size),
                                    sizeof(size_t));
  if (ret != 0)
  {
    goto read_lens_error;
  }
  ret = mbedtls_mpi_write_binary_le(exp_len, (unsigned char *)(exp_size),
                                    sizeof(size_t));
  if (ret != 0)
  {
    goto read_lens_error;
  }
  ret = mbedtls_mpi_write_binary_le(mod_len, (unsigned char *)(mod_size),
                                    sizeof(size_t));
  if (ret != 0)
  {
    goto read_lens_error;
  }

  /* NOTE: if success, don't free base_len/exp_len/mod_len */
  return 0;

read_lens_error:
  mbedtls_mpi_free(base_len);
  mbedtls_mpi_free(exp_len);
  mbedtls_mpi_free(mod_len);
  return ERROR_MOD_EXP;
}

// modexpMultComplexity implements bigModexp multComplexity formula, as defined
// in EIP-198
//
// def mult_complexity(x):
//    if x <= 64: return x ** 2
//    elif x <= 1024: return x ** 2 // 4 + 96 * x - 3072
//    else: return x ** 2 // 16 + 480 * x - 199680
//
// where is x is max(length_of_MODULUS, length_of_BASE)
uint128_t modexp_mult_complexity(uint128_t x)
{
  if (x <= 64)
  {
    return x * x;
  }
  else if (x <= 1024)
  {
    return x * x / 4 + 96 * x - 3072;
  }
  else
  {
    return x * x / 16 + 480 * x - 199680;
  }
}

/* EIP-2565: Big integer modular exponentiation: false */
int big_mod_exp_required_gas(const uint8_t *input, const size_t input_size,
                             uint64_t *target_gas)
{
  int ret;
  mbedtls_mpi base_len;
  mbedtls_mpi exp_len;
  mbedtls_mpi mod_len;
  size_t base_size;
  size_t exp_size;
  size_t mod_size;
  ret = read_lens(input, input_size, &base_len, &exp_len, &mod_len, &base_size,
                  &exp_size, &mod_size);
  if (ret != 0)
  {
    ckb_debug("0");
    /* if read_lens() failed, base_len/exp_len/mod_len already freed */
    return ERROR_MOD_EXP;
  }

  // Retrieve the head 32 bytes of exp for the adjusted exponent length
  int return_value = 0;
  mbedtls_mpi exp_head;
  mbedtls_mpi adj_exp_len;
  mbedtls_mpi gas_big;
  mbedtls_mpi_init(&exp_head);
  mbedtls_mpi_init(&adj_exp_len);
  mbedtls_mpi_init(&gas_big);

  size_t exp_head_size = exp_size > 32 ? 32 : exp_size;
  int msb = 0;
  int exp_head_bitlen = 0;
  size_t base_gas = 0;
  uint128_t gas = 0;

  const size_t content_size = base_size + exp_size + mod_size;
  const size_t copy_size = input_size > content_size + 96
                               ? content_size
                               : (input_size > 96 ? input_size - 96 : 0);
  uint8_t *content = (uint8_t *)malloc(content_size);
  if (content == NULL)
  {
    return_value = FATAL_PRECOMPILED_CONTRACTS;
    goto mod_exp_gas_cleanup;
  }
  memset(content, 0, content_size);
  memcpy(content, input + 96, copy_size);

  ret = mbedtls_mpi_read_binary(&exp_head, content + base_size, exp_head_size);
  if (ret != 0)
  {
    ckb_debug("1");
    return_value = ERROR_MOD_EXP;
    goto mod_exp_gas_cleanup;
  }
  // Calculate the adjusted exponent length
  exp_head_bitlen = mbedtls_mpi_bitlen(&exp_head);
  if (exp_head_bitlen > 0)
  {
    msb = exp_head_bitlen - 1;
  }
  if (exp_size > 32)
  {
    ret = mbedtls_mpi_sub_int(&adj_exp_len, &exp_len, 32);
    if (ret != 0)
    {
      ckb_debug("2");
      return_value = ERROR_MOD_EXP;
      goto mod_exp_gas_cleanup;
    }
    ret = mbedtls_mpi_mul_int(&adj_exp_len, &adj_exp_len, 8);
    if (ret != 0)
    {
      ckb_debug("3");
      return_value = ERROR_MOD_EXP;
      goto mod_exp_gas_cleanup;
    }
  }
  ret = mbedtls_mpi_add_int(&adj_exp_len, &adj_exp_len, msb);
  if (ret != 0)
  {
    ckb_debug("4");
    return_value = ERROR_MOD_EXP;
    goto mod_exp_gas_cleanup;
  }
  // Calculate the gas cost of the operation
  base_gas = mod_size > base_size ? mod_size : base_size;
  gas = modexp_mult_complexity((uint128_t)base_gas);
  ret = mbedtls_mpi_read_binary_le(&gas_big, (unsigned char *)(&gas), 16);
  if (ret != 0)
  {
    return_value = ERROR_MOD_EXP;
    goto mod_exp_gas_cleanup;
  }
  if (mbedtls_mpi_cmp_int(&adj_exp_len, 1) > 0)
  {
    ret = mbedtls_mpi_mul_mpi(&gas_big, &gas_big, &adj_exp_len);
    if (ret != 0)
    {
      return_value = ERROR_MOD_EXP;
      goto mod_exp_gas_cleanup;
    }
  }
  ret = mbedtls_mpi_div_int(&gas_big, NULL, &gas_big, 20);
  if (ret != 0)
  {
    return_value = ERROR_MOD_EXP;
    goto mod_exp_gas_cleanup;
  }

  if (mbedtls_mpi_bitlen(&gas_big) > 64)
  {
    *target_gas = UINT64_MAX;
  }
  else
  {
    ret = mbedtls_mpi_write_binary_le(&gas_big, (unsigned char *)(target_gas), sizeof(uint64_t));
    if (ret != 0)
    {
      return_value = ERROR_MOD_EXP;
      goto mod_exp_gas_cleanup;
    }
  }

mod_exp_gas_cleanup:
  mbedtls_mpi_free(&base_len);
  mbedtls_mpi_free(&exp_len);
  mbedtls_mpi_free(&mod_len);

  mbedtls_mpi_free(&exp_head);
  mbedtls_mpi_free(&adj_exp_len);
  mbedtls_mpi_free(&gas_big);
  free(content);
  return return_value;
}

/* EIP-2565: Big integer modular exponentiation: false */
int big_mod_exp(gw_context_t *ctx,
                const uint8_t *code_data,
                const size_t code_size,
                bool is_static_call,
                const uint8_t *input_src,
                const size_t input_size, uint8_t **output,
                size_t *output_size)
{
  int ret;
  mbedtls_mpi base_len;
  mbedtls_mpi exp_len;
  mbedtls_mpi mod_len;
  size_t base_size;
  size_t exp_size;
  size_t mod_size;
  ret = read_lens(input_src, input_size, &base_len, &exp_len, &mod_len,
                  &base_size, &exp_size, &mod_size);
  if (ret != 0)
  {
    /* if read_lens() failed, base_len/exp_len/mod_len already freed */
    return ERROR_MOD_EXP;
  }

  if (mbedtls_mpi_cmp_int(&base_len, 0) == 0 &&
      mbedtls_mpi_cmp_int(&mod_len, 0) == 0)
  {
    *output = NULL;
    *output_size = 0;
    mbedtls_mpi_free(&base_len);
    mbedtls_mpi_free(&exp_len);
    mbedtls_mpi_free(&mod_len);
    return 0;
  }

  int return_value = 0;
  mbedtls_mpi base;
  mbedtls_mpi exp;
  mbedtls_mpi mod;
  mbedtls_mpi result;
  mbedtls_mpi_init(&base);
  mbedtls_mpi_init(&exp);
  mbedtls_mpi_init(&mod);
  mbedtls_mpi_init(&result);

  const size_t content_size = base_size + exp_size + mod_size;
  const size_t copy_size = input_size > content_size + 96
                               ? content_size
                               : (input_size > 96 ? input_size - 96 : 0);
  uint8_t *content = (uint8_t *)malloc(content_size);
  if (content == NULL)
  {
    return_value = FATAL_PRECOMPILED_CONTRACTS;
    goto mod_exp_cleanup;
  }
  memset(content, 0, content_size);
  memcpy(content, input_src + 96, copy_size);

  ret = mbedtls_mpi_read_binary(&base, content, base_size);
  if (ret != 0)
  {
    return_value = ERROR_MOD_EXP;
    goto mod_exp_cleanup;
  }
  ret = mbedtls_mpi_read_binary(&exp, content + base_size, exp_size);
  if (ret != 0)
  {
    return_value = ERROR_MOD_EXP;
    goto mod_exp_cleanup;
  }
  ret = mbedtls_mpi_read_binary(&mod, content + base_size + exp_size, mod_size);
  if (ret != 0)
  {
    return_value = ERROR_MOD_EXP;
    goto mod_exp_cleanup;
  }

  *output = (uint8_t *)malloc(mod_size);
  if (*output == NULL)
  {
    return_value = ERROR_MOD_EXP;
    goto mod_exp_cleanup;
  }
  *output_size = mod_size;
  if (mbedtls_mpi_bitlen(&mod) == 0)
  {
    memset(*output, 0, mod_size);
    goto mod_exp_cleanup;
  }

  ret = mbedtls_mpi_exp_mod(&result, &base, &exp, &mod, NULL);
  if (ret != 0)
  {
    return_value = ERROR_MOD_EXP;
    goto mod_exp_cleanup;
  }
  ret = mbedtls_mpi_write_binary(&result, *output, mod_size);
  if (ret != 0)
  {
    return_value = ERROR_MOD_EXP;
    goto mod_exp_cleanup;
  }

mod_exp_cleanup:
  mbedtls_mpi_free(&base_len);
  mbedtls_mpi_free(&exp_len);
  mbedtls_mpi_free(&mod_len);

  mbedtls_mpi_free(&base);
  mbedtls_mpi_free(&exp);
  mbedtls_mpi_free(&mod);
  mbedtls_mpi_free(&result);

  free(content);
  return return_value;
}

static uint8_t precomputed[10][16] = {
    {0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15},
    {14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3},
    {11, 12, 5, 15, 8, 0, 2, 13, 10, 3, 7, 9, 14, 6, 1, 4},
    {7, 3, 13, 11, 9, 1, 12, 14, 2, 5, 4, 15, 6, 10, 0, 8},
    {9, 5, 2, 10, 0, 7, 4, 15, 14, 11, 6, 3, 1, 12, 8, 13},
    {2, 6, 0, 8, 12, 10, 11, 3, 4, 7, 15, 1, 13, 5, 14, 9},
    {12, 1, 14, 4, 5, 15, 13, 10, 0, 6, 9, 8, 7, 3, 2, 11},
    {13, 7, 12, 3, 11, 14, 1, 9, 5, 15, 8, 2, 0, 4, 6, 10},
    {6, 14, 11, 0, 15, 9, 3, 8, 12, 13, 1, 10, 2, 7, 4, 5},
    {10, 8, 7, 1, 2, 4, 6, 5, 15, 9, 3, 13, 11, 14, 12, 0},
};
static uint64_t iv[8] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
};

int blake2f_required_gas(const uint8_t *input, const size_t input_size,
                         uint64_t *target_gas)
{
  if (input_size != BLAKE2F_INPUT_LENGTH)
  {
    *target_gas = 0;
    return 0;
  }
  uint32_t gas = ((uint32_t)input[0] << 24 | (uint32_t)input[1] << 16 |
                  (uint32_t)input[2] << 8 | (uint32_t)input[3] << 0);
  *target_gas = (uint64_t)gas;
  return 0;
}

uint64_t rotate_left64(uint64_t x, int k)
{
  size_t n = 64;
  size_t s = (size_t)(k) & (n - 1);
  return x << s | x >> (n - s);
}

/* function f_generic is translated from https://github.com/ethereum/go-ethereum/blob/8647233a8ec2a2410a078013ca12c38fdc229866/crypto/blake2b/blake2b_generic.go#L46-L180 */
void f_generic(uint64_t h[8], uint64_t m[16], uint64_t c0, uint64_t c1,
               uint64_t flag, uint64_t rounds)
{
  uint64_t v0 = h[0];
  uint64_t v1 = h[1];
  uint64_t v2 = h[2];
  uint64_t v3 = h[3];
  uint64_t v4 = h[4];
  uint64_t v5 = h[5];
  uint64_t v6 = h[6];
  uint64_t v7 = h[7];
  uint64_t v8 = iv[0];
  uint64_t v9 = iv[1];
  uint64_t v10 = iv[2];
  uint64_t v11 = iv[3];
  uint64_t v12 = iv[4];
  uint64_t v13 = iv[5];
  uint64_t v14 = iv[6];
  uint64_t v15 = iv[7];
  v12 ^= c0;
  v13 ^= c1;
  v14 ^= flag;

  for (uint64_t i = 0; i < rounds; i++)
  {
    uint8_t *s = precomputed[i % 10];

    v0 += m[s[0]];
    v0 += v4;
    v12 ^= v0;
    v12 = rotate_left64(v12, -32);
    v8 += v12;
    v4 ^= v8;
    v4 = rotate_left64(v4, -24);
    v1 += m[s[1]];
    v1 += v5;
    v13 ^= v1;
    v13 = rotate_left64(v13, -32);
    v9 += v13;
    v5 ^= v9;
    v5 = rotate_left64(v5, -24);
    v2 += m[s[2]];
    v2 += v6;
    v14 ^= v2;
    v14 = rotate_left64(v14, -32);
    v10 += v14;
    v6 ^= v10;
    v6 = rotate_left64(v6, -24);
    v3 += m[s[3]];
    v3 += v7;
    v15 ^= v3;
    v15 = rotate_left64(v15, -32);
    v11 += v15;
    v7 ^= v11;
    v7 = rotate_left64(v7, -24);

    v0 += m[s[4]];
    v0 += v4;
    v12 ^= v0;
    v12 = rotate_left64(v12, -16);
    v8 += v12;
    v4 ^= v8;
    v4 = rotate_left64(v4, -63);
    v1 += m[s[5]];
    v1 += v5;
    v13 ^= v1;
    v13 = rotate_left64(v13, -16);
    v9 += v13;
    v5 ^= v9;
    v5 = rotate_left64(v5, -63);
    v2 += m[s[6]];
    v2 += v6;
    v14 ^= v2;
    v14 = rotate_left64(v14, -16);
    v10 += v14;
    v6 ^= v10;
    v6 = rotate_left64(v6, -63);
    v3 += m[s[7]];
    v3 += v7;
    v15 ^= v3;
    v15 = rotate_left64(v15, -16);
    v11 += v15;
    v7 ^= v11;
    v7 = rotate_left64(v7, -63);

    v0 += m[s[8]];
    v0 += v5;
    v15 ^= v0;
    v15 = rotate_left64(v15, -32);
    v10 += v15;
    v5 ^= v10;
    v5 = rotate_left64(v5, -24);
    v1 += m[s[9]];
    v1 += v6;
    v12 ^= v1;
    v12 = rotate_left64(v12, -32);
    v11 += v12;
    v6 ^= v11;
    v6 = rotate_left64(v6, -24);
    v2 += m[s[10]];
    v2 += v7;
    v13 ^= v2;
    v13 = rotate_left64(v13, -32);
    v8 += v13;
    v7 ^= v8;
    v7 = rotate_left64(v7, -24);
    v3 += m[s[11]];
    v3 += v4;
    v14 ^= v3;
    v14 = rotate_left64(v14, -32);
    v9 += v14;
    v4 ^= v9;
    v4 = rotate_left64(v4, -24);

    v0 += m[s[12]];
    v0 += v5;
    v15 ^= v0;
    v15 = rotate_left64(v15, -16);
    v10 += v15;
    v5 ^= v10;
    v5 = rotate_left64(v5, -63);
    v1 += m[s[13]];
    v1 += v6;
    v12 ^= v1;
    v12 = rotate_left64(v12, -16);
    v11 += v12;
    v6 ^= v11;
    v6 = rotate_left64(v6, -63);
    v2 += m[s[14]];
    v2 += v7;
    v13 ^= v2;
    v13 = rotate_left64(v13, -16);
    v8 += v13;
    v7 ^= v8;
    v7 = rotate_left64(v7, -63);
    v3 += m[s[15]];
    v3 += v4;
    v14 ^= v3;
    v14 = rotate_left64(v14, -16);
    v9 += v14;
    v4 ^= v9;
    v4 = rotate_left64(v4, -63);
  }
  h[0] ^= v0 ^ v8;
  h[1] ^= v1 ^ v9;
  h[2] ^= v2 ^ v10;
  h[3] ^= v3 ^ v11;
  h[4] ^= v4 ^ v12;
  h[5] ^= v5 ^ v13;
  h[6] ^= v6 ^ v14;
  h[7] ^= v7 ^ v15;
}

/* https://eips.ethereum.org/EIPS/eip-152 */
int blake2f(gw_context_t *ctx,
            const uint8_t *code_data,
            const size_t code_size,
            bool is_static_call,
            const uint8_t *input_src,
            const size_t input_size, uint8_t **output, size_t *output_size)
{
  if (input_size != BLAKE2F_INPUT_LENGTH)
  {
    return ERROR_BLAKE2F_INVALID_INPUT_LENGTH;
  }
  if (input_src[212] != BLAKE2F_NON_FINAL_BLOCK_BYTES &&
      input_src[212] != BLAKE2F_FINAL_BLOCK_BYTES)
  {
    return ERROR_BLAKE2F_INVALID_FINAL_FLAG;
  }

  uint32_t rounds =
      ((uint32_t)input_src[0] << 24 | (uint32_t)input_src[1] << 16 |
       (uint32_t)input_src[2] << 8 | (uint32_t)input_src[3] << 0);
  bool final = input_src[212] == BLAKE2F_FINAL_BLOCK_BYTES;
  uint64_t h[8];
  uint64_t m[16];
  uint64_t t[2];
  for (size_t i = 0; i < 8; i++)
  {
    size_t offset = 4 + i * 8;
    memcpy(&h[i], input_src + offset, sizeof(uint64_t));
  }
  for (size_t i = 0; i < 16; i++)
  {
    size_t offset = 68 + i * 8;
    memcpy(&m[i], input_src + offset, sizeof(uint64_t));
  }
  memcpy(&t[0], input_src + 196, sizeof(uint64_t));
  memcpy(&t[1], input_src + 204, sizeof(uint64_t));

  uint64_t flag = final ? 0xFFFFFFFFFFFFFFFF : 0;
  /* TODO: maybe improve performance */
  f_generic(h, m, t[0], t[1], flag, (uint64_t)rounds);

  *output = (uint8_t *)malloc(64);
  if (*output == NULL)
  {
    return FATAL_PRECOMPILED_CONTRACTS;
  }
  *output_size = 64;
  for (size_t i = 0; i < 8; i++)
  {
    size_t offset = i * 8;
    memcpy(*output + offset, (uint8_t *)(&h[i]), 8);
  }
  return 0;
}

int parse_curve_point(void *target, uint8_t *bytes)
{
  intx::uint256 *p = (intx::uint256 *)target;
  p[0] = intx::be::unsafe::load<intx::uint256>(bytes);
  p[1] = intx::be::unsafe::load<intx::uint256>(bytes + 32);
  if (p[0] == 0 && p[1] == 0)
  {
    p[2] = 0;
  }
  else
  {
    p[2] = 1;
    if (!bn128::g1::is_on_curve(p))
    {
      ckb_debug("bn256: malformed point");
      return ERROR_BN256_INVALID_POINT;
    }
  }
  return 0;
}

int parse_twist_point(void *target, uint8_t *bytes)
{
  /* FIXME: wait for pairing implementation ready */
  return 0;
}

/* bn256AddIstanbul */
int bn256_add_istanbul_gas(const uint8_t *input_src,
                           const size_t input_size,
                           uint64_t *gas)
{
  *gas = BN256_ADD_GAS_ISTANBUL;
  return 0;
}

int bn256_add_istanbul(gw_context_t *ctx,
                       const uint8_t *code_data,
                       const size_t code_size,
                       bool is_static_call,
                       const uint8_t *input_src,
                       const size_t input_size,
                       uint8_t **output, size_t *output_size)
{
  int ret;
  /* If the input is shorter than expected, it is assumed to be virtually padded
     with zeros at the end (i.e. compatible with the semantics of the
     CALLDATALOAD opcode). If the input is longer than expected, surplus bytes
     at the end are ignored. */
  uint8_t real_input[128] = {0};
  size_t real_size = input_size > 128 ? 128 : input_size;
  /* point[3] = point[2]² */
  intx::uint256 x[3];
  intx::uint256 y[3];
  intx::uint256 res[3];

  memcpy(real_input, input_src, real_size);
  ret = parse_curve_point((void *)x, real_input);
  if (ret != 0)
  {
    return ret;
  }
  ret = parse_curve_point((void *)y, real_input + 64);
  if (ret != 0)
  {
    return ret;
  }
  bn128::alt_bn128_add(x, y, res);

  *output = (uint8_t *)malloc(64);
  if (*output == NULL)
  {
    return FATAL_PRECOMPILED_CONTRACTS;
  }
  *output_size = 64;
  intx::be::unsafe::store(*output, res[0]);
  intx::be::unsafe::store(*output + 32, res[1]);
  return 0;
}

/* bn256ScalarMulIstanbul */
int bn256_scalar_mul_istanbul_gas(const uint8_t *input_src,
                                  const size_t input_size,
                                  uint64_t *gas)
{
  *gas = BN256_SCALAR_MUL_GAS_ISTANBUL;
  return 0;
}

int bn256_scalar_mul_istanbul(gw_context_t *ctx,
                              const uint8_t *code_data,
                              const size_t code_size,
                              bool is_static_call,
                              const uint8_t *input_src,
                              const size_t input_size,
                              uint8_t **output, size_t *output_size)
{
  int ret;
  uint8_t real_input[96] = {0};
  size_t real_size = input_size > 96 ? 96 : input_size;
  intx::uint256 x[3];
  intx::uint256 res[3];

  memcpy(real_input, input_src, real_size);
  ret = parse_curve_point((void *)x, real_input);
  if (ret != 0)
  {
    return ret;
  }
  intx::uint256 n = intx::be::unsafe::load<intx::uint256>(real_input + 64);
  bn128::alt_bn128_mul(x, n, res);

  *output = (uint8_t *)malloc(64);
  if (*output == NULL)
  {
    return FATAL_PRECOMPILED_CONTRACTS;
  }
  *output_size = 64;
  intx::be::unsafe::store(*output, res[0]);
  intx::be::unsafe::store(*output + 32, res[1]);
  return 0;
}

/* bn256PairingIstanbul */
int bn256_pairing_istanbul_gas(const uint8_t *input_src,
                               const size_t input_size,
                               uint64_t *gas)
{
  *gas = BN256_PAIRING_BASE_GAS_ISTANBUL + ((uint64_t)input_size / 192 * BN256_PAIRING_PERPOINT_GAS_ISTANBUL);
  return 0;
}

/* FIXME: Pairing is not supported due to it's high cycle cost. */
int bn256_pairing_istanbul(gw_context_t *ctx,
                           const uint8_t *code_data,
                           const size_t code_size,
                           bool is_static_call,
                           const uint8_t *input_src,
                           const size_t input_size,
                           uint8_t **output, size_t *output_size)
{
  if (input_size % 192 > 0)
  {
    return ERROR_BN256_PAIRING;
  }

  int ret;
  size_t length = input_size / 192;
  /* G1[] */
  intx::uint256 *cs = (intx::uint256 *)malloc(length * 4 * sizeof(intx::uint256));
  if (cs == NULL)
  {
    return FATAL_PRECOMPILED_CONTRACTS;
  }
  /* G2[] */
  intx::uint256 *ts = (intx::uint256 *)malloc(length * 4 * sizeof(intx::uint256));
  if (ts == NULL)
  {
    return FATAL_PRECOMPILED_CONTRACTS;
  }
  for (size_t i = 0; i < input_size; i += 192)
  {
    ret = parse_curve_point((void *)(cs + i / 192 * 4), (uint8_t *)input_src + i);
    if (ret != 0)
    {
      return ret;
    }
    ret = parse_twist_point((void *)(ts + i / 192 * 4), (uint8_t *)input_src + i + 64);
    if (ret != 0)
    {
      return ret;
    }
  }
  ckb_debug("pairing is unsupported yet due to very high cycle cost!");
  return ERROR_BN256_PAIRING;
}

/*
  rsa signature validate
*/
int get_rsa_info(uint32_t pubkey_e, const uint8_t *pubkey_n, uint32_t pubkey_n_size, uint8_t md_type,
                 const uint8_t *signature_buffer, uint32_t signature_size,
                 uint8_t **output, uint32_t *output_size)
{
  if (pubkey_n_size != signature_size)
  {
    return ERROR_RSA_INVALID_LENGTH;
  }

  if (md_type != CKB_MD_NONE && md_type != CKB_MD_SHA256)
  {
    return ERROR_RSA_INVALID_MD_TYPE;
  }
  uint32_t pubkey_size = (uint32_t)pubkey_n_size * 8;

  *output_size = 8 + pubkey_n_size * 2;
  *output = (uint8_t *)malloc(*output_size);

  (*output)[0] = CKB_VERIFY_RSA;
  (*output)[1] = (uint8_t)(pubkey_size / (uint32_t)1024);
  (*output)[2] = CKB_PKCS_15;
  (*output)[3] = md_type;

  memcpy((*output) + 4, (uint8_t *)(&pubkey_e), 4);
  memcpy((*output) + 8, pubkey_n, pubkey_n_size);
  memcpy((*output) + 8 + pubkey_n_size, signature_buffer, signature_size);

  return 0;
}
int internel_rsa_validate_signature(uint32_t pubkey_e, const uint8_t *pubkey_n, uint32_t pubkey_n_size, uint8_t md_type,
                                    const uint8_t *msg_buf, uint32_t msg_size,
                                    const uint8_t *signature_buffer, uint32_t signature_size)
{
  int ret = 0;

  uint8_t *rsa_info;
  uint32_t rsa_info_size;
  ret = get_rsa_info(pubkey_e, pubkey_n, pubkey_n_size, md_type,
                     signature_buffer, signature_size,
                     &rsa_info, &rsa_info_size);

  debug_print_data("get rsa info: ", rsa_info, rsa_info_size);
  debug_print_int("get rsa info size: ", rsa_info_size);
  if (ret != 0)
  {
    debug_print_int("get rsa ret: ", ret);
    return ret;
  }
  ret = validate_signature(NULL, rsa_info, rsa_info_size, msg_buf, msg_size, NULL, NULL);
  if (ret != 0)
  {
    debug_print_int("validate signature ret: ", ret);
  }
  free(rsa_info);
  return ret;
}
void reverse_vec_n(uint8_t *input, uint32_t n)
{
  uint8_t c;
  for (int i = 0; i < n / 2; i++)
  {
    c = *(input + i);
    *(input + i) = *(input + n - 1 - i);
    *(input + n - 1 - i) = c;
  }
}
/*
 * validate rsa

  ===============
    input[0..4]                                                                     => pubkey e
    input[4..8]                                                                     => pubkey n size
    input[8..8 + pubkey_n_size]                                                     => pubkey n
    input[8 + pubkey_n_size..12 + pubkey_n_size]                                     => md type: 0 NONE, 6 SHA256
    input[12 + pubkey_n_size..16 + pubkey_n_size ]                                   => message size
    input[16 + pubkey_n_size..16 + pubkey_n_size + msg_size]                        => message
    input[16 + pubkey_n_size + msg_size..20 + pubkey_n_size + msg_size]             => signature size
    input[20 + pubkey_n_size + msg_size..20 + pubkey_n_size + msg_size + sig_size]  => signature
 */
int rsa_validate_signature(gw_context_t *ctx,
                           const uint8_t *code_data,
                           const size_t code_size,
                           bool is_static_call,
                           const uint8_t *input_src,
                           const size_t input_size,
                           uint8_t **output, size_t *output_size)
{
  uint8_t *mut_input_src = (uint8_t *)input_src;
  reverse_vec_n((uint8_t *)(mut_input_src), 4);
  uint32_t *pubkey_e = (uint32_t *)(mut_input_src);
  reverse_vec_n((uint8_t *)(mut_input_src + 4), 4);
  uint32_t *pubkey_n_size = (uint32_t *)(mut_input_src + 4);
  reverse_vec_n((uint8_t *)(mut_input_src + 8), *pubkey_n_size);
  uint8_t *pubkey_n = mut_input_src + 8;
  reverse_vec_n((uint8_t *)(mut_input_src + 8 + *pubkey_n_size), 4);
  const uint32_t *md_type = (uint32_t *)(mut_input_src + 8 + *pubkey_n_size);
  debug_print_int("md type: ", *md_type);
  reverse_vec_n((uint8_t *)(mut_input_src + 12 + *pubkey_n_size), 4);
  uint32_t *msg_size = (uint32_t *)(mut_input_src + 12 + *pubkey_n_size);
  uint8_t *msg = mut_input_src + 16 + *pubkey_n_size;
  reverse_vec_n((uint8_t *)(mut_input_src + 16 + (unsigned long)*pubkey_n_size + (unsigned long)*msg_size), 4);
  uint32_t *sig_size = (uint32_t *)(mut_input_src + 16 + (unsigned long)*pubkey_n_size + (unsigned long)*msg_size);
  uint8_t *sig = mut_input_src + 20 + (unsigned long)*pubkey_n_size + (unsigned long)*msg_size;
  debug_print_data("rsa validate input: ", input_src, input_size);
  debug_print_data("rsa validate message: ", msg, *msg_size);
  debug_print_int("rsa validate message size: ", *msg_size);
  debug_print_data("rsa validate sig: ", sig, *sig_size);
  debug_print_int("rsa validate sig size: ", *sig_size);
  debug_print_int("rsa validate e: ", *pubkey_e);
  debug_print_data("rsa validate n: ", pubkey_n, *pubkey_n_size);
  debug_print_int("rsa validate n size: ", *pubkey_n_size);

  int res = internel_rsa_validate_signature(*pubkey_e, pubkey_n, *pubkey_n_size,
                                            (uint8_t)*md_type, msg, *msg_size,
                                            sig, *sig_size);
  *output_size = 4;
  *output = (uint8_t *)malloc(4);
  memcpy(*output, (uint8_t *)(&res), 4);

  return 0;
}

int rsa_validate_gas(const uint8_t *input_src,
                     const size_t input_size,
                     uint64_t *gas)
{
  *gas = 3000;
  return 0;
}

/*
 * return:
 *  0 success
 *  -1 expected `0x`
 *  -2 expected 64 hex bytes 
*/
int deal_email_subject(uint8_t *subject_header, uint32_t subject_header_len, uint8_t **sig_hash)
{
  for (uint32_t i = 0; i < subject_header_len - 64 - 2; i++)
  {
    if (subject_header[i] == '0' &&
        (subject_header[i + 1] = 'x' || subject_header[i + 1] == 'X'))
    {
      *sig_hash = (uint8_t *)malloc(32);
      for (int j = 0; j < 32; j++)
      {
        uint8_t part1 = subject_header[i + 2 + j * 2];
        uint8_t part2 = subject_header[i + 2 + j * 2 + 1];
        if (part1 >= 'a' && part1 <= 'f')
        {
          part1 = part1 - 'a' + 10;
        }
        else if (part1 >= '0' && part1 <= '9')
        {
          part1 = part1 - '0';
        }
        else
        {
          goto invalid_hex;
        }

        if (part2 >= 'a' && part2 <= 'f')
        {
          part2 = part2 - 'a' + 10;
        }
        else if (part2 >= '0' && part2 <= '9')
        {
          part2 = part2 - '0';
        }
        else
        {
          goto invalid_hex;
        }
        (*sig_hash)[j] = part1 * 16 + part2;
        continue;
      invalid_hex:
        free(*sig_hash);
        return -2;
      }
      return 0;
    }
  }
  return -2;
}

/*
 * get email pointer
*/
int contract_get_email(gw_context_t *ctx,
                       const uint8_t *code_data,
                       const size_t code_size,
                       bool is_static_call,
                       const uint8_t *input_src,
                       const size_t input_size,
                       uint8_t **output, size_t *output_size)
{
  Email *email = NULL;
  int ret = 0;
  ret = get_email(input_src, input_size, &email);
  if (ret != 0)
  {
    return ret;
  }
  uintptr_t email_pointer = (uintptr_t)email;
  memcpy(*output, (uint8_t *)(&email_pointer), sizeof(uintptr_t *));
  *output_size = sizeof(uintptr_t *);
  return ret;
}

/*
 * get email dkim sig header
*/
int email_get_dkim_sig_header(gw_context_t *ctx,
                              const uint8_t *code_data,
                              const size_t code_size,
                              bool is_static_call,
                              const uint8_t *input_src,
                              const size_t input_size,
                              uint8_t **output, size_t *output_size)
{
  uintptr_t *p = (uintptr_t *)input_src;
  Email *email = (Email *)(*p);
  int ret = 0;
  const uint8_t *const *dkim_sig = NULL;
  const uintptr_t *dkim_sig_len = NULL;
  const uint8_t *const *dkim_selector = NULL;
  const uintptr_t *dkim_selector_len = NULL;
  const uint8_t *const *dkim_sdid = NULL;
  const uintptr_t *dkim_sdid_len = NULL;
  uintptr_t dkim_sig_num = 0;
  ret = get_email_dkim_sig(email,
                           &dkim_sig, &dkim_sig_len, &dkim_selector, &dkim_selector_len,
                           &dkim_sdid, &dkim_sdid_len, &dkim_sig_num);
  if (ret != 0)
  {
    return ret;
  }
  if (dkim_sig_num == 0)
  {
    return 2;
  }
  debug_print_data("dkim selector: ", *dkim_selector, dkim_selector_len[0]);
  debug_print_int("dkim selector len: ", dkim_selector_len[0]);
  debug_print_data("dkim sdid: ", *dkim_sdid, dkim_sdid_len[0]);
  debug_print_int("dkim sdid len: ", dkim_sdid_len[0]);
  debug_print_data("dkim sig: ", *dkim_sig, dkim_sig_len[0]);
  debug_print_int("dkim sig len: ", dkim_sig_len[0]);
  // *output_size = dkim_sdid_len[0];
  // *output = (uint8_t *)*dkim_sdid;
  *output_size = 64 + 32 + 32 + dkim_sig_len[0];
  // *output_size = 32;
  *output = (uint8_t *)malloc(*output_size);
  memset(*output, 0, *output_size);

  memcpy(*output, dkim_selector[0], dkim_selector_len[0]);
  memcpy(*output + 32, dkim_sdid[0], dkim_sdid_len[0]);
  (*output)[32 + 32 + 32 - 1] = 96;
  memcpy(*output + 32 + 32 + 32, dkim_sig_len, sizeof(uintptr_t));
  reverse_vec_n(*output + 32 + 32 + 32, 32);
  memcpy(*output + 32 + 32 + 32 + 32, dkim_sig[0], dkim_sig_len[0]);
  debug_print_data("output: ", *output, *output_size);
  debug_print_int("output len: ", *output_size);

  for (int i = 0; i < dkim_sig_num; i++)
  {
    rust_free_vec_u8((uint8_t *)(dkim_sdid[i]), dkim_sdid_len[i], dkim_sdid_len[i]);
    rust_free_vec_u8((uint8_t *)(dkim_selector[i]), dkim_selector_len[i], dkim_selector_len[i]);
    rust_free_vec_u8((uint8_t *)(dkim_sig[i]), dkim_sig_len[i], dkim_sig_len[i]);
  }
  rust_free_ptr_vec((uint8_t **)dkim_sdid, dkim_sig_num, dkim_sig_num);
  rust_free_ptr_vec((uint8_t **)dkim_selector, dkim_sig_num, dkim_sig_num);
  rust_free_ptr_vec((uint8_t **)dkim_sig, dkim_sig_num, dkim_sig_num);
  rust_free_vec_usize((uintptr_t *)dkim_sig_len, dkim_sig_num, dkim_sig_num);
  rust_free_vec_usize((uintptr_t *)dkim_sdid_len, dkim_sig_num, dkim_sig_num);
  rust_free_vec_usize((uintptr_t *)dkim_selector_len, dkim_sig_num, dkim_sig_num);

  return ret;
}

/*
 * get email dkim message header
*/
int email_get_dkim_message_header(gw_context_t *ctx,
                                  const uint8_t *code_data,
                                  const size_t code_size,
                                  bool is_static_call,
                                  const uint8_t *input_src,
                                  const size_t input_size,
                                  uint8_t **output, size_t *output_size)
{
  uintptr_t *p = (uintptr_t *)input_src;
  Email *email = (Email *)(*p);
  int ret = 0;
  const uint8_t *const *dkim_msg = NULL;
  const uintptr_t *dkim_msg_len = NULL;
  uintptr_t dkim_msg_num = 0;
  ret = get_email_dkim_msg(email, &dkim_msg, &dkim_msg_len, &dkim_msg_num);
  if (ret != 0)
  {
    return ret;
  }
  if (dkim_msg_num == 0)
  {
    return 2;
  }

  *output_size = (size_t)(dkim_msg_len[0]);
  // *output_size = 32;
  *output = (uint8_t *)malloc(*output_size);
  memset(*output, 0, *output_size);
  memcpy(*output, *dkim_msg, *output_size);
  for (int i = 0; i++; i < dkim_msg_num)
  {
    rust_free_vec_u8((uint8_t *)(dkim_msg[i]), dkim_msg_len[i], dkim_msg_len[i]);
  }
  rust_free_ptr_vec((uint8_t **)dkim_msg, dkim_msg_num, dkim_msg_num);
  rust_free_vec_usize((uintptr_t *)dkim_msg_len, dkim_msg_num, dkim_msg_num);

  debug_print_data("dkim message: ", *output, *output_size);
  debug_print_int("dkim message len: ", *output_size);
  return ret;
}

/*
 * get email dkim message header
*/
int email_get_from_header(gw_context_t *ctx,
                          const uint8_t *code_data,
                          const size_t code_size,
                          bool is_static_call,
                          const uint8_t *input_src,
                          const size_t input_size,
                          uint8_t **output, size_t *output_size)
{
  uintptr_t *p = (uintptr_t *)input_src;
  Email *email = (Email *)(*p);
  int ret = 0;
  uint8_t *from = NULL;
  uintptr_t from_len = NULL;
  ret = get_email_from_header(email, &from, &from_len);
  if (ret != 0)
  {
    return ret;
  }

  *output_size = from_len;
  *output = (uint8_t *)malloc(*output_size);
  memset(*output, 0, *output_size);

  rust_free_vec_u8(from, from_len, from_len);

  debug_print_data("from header: ", *output, *output_size);
  debug_print_int("from header len: ", *output_size);
  return ret;
}

/*
 * get email subject header
*/
int email_get_subject_header(gw_context_t *ctx,
                          const uint8_t *code_data,
                          const size_t code_size,
                          bool is_static_call,
                          const uint8_t *input_src,
                          const size_t input_size,
                          uint8_t **output, size_t *output_size)
{
  uintptr_t *p = (uintptr_t *)input_src;
  Email *email = (Email *)(*p);
  int ret = 0;
  uint8_t *subject = NULL;
  uintptr_t subject_len = NULL;
  ret = get_email_subject_header(email, &subject, &subject_len);
  if (ret != 0)
  {
    return ret;
  }

  *output_size = subject_len;
  *output = (uint8_t *)malloc(*output_size);
  memset(*output, 0, *output_size);

  rust_free_vec_u8(subject, subject_len, subject_len);

  debug_print_data("subject header: ", *output, *output_size);
  debug_print_int("subject header len: ", *output_size);
  return ret;
}
/*
 * validate dkim

  ===============
    input[0 .. 4]                                                                                                       => email dkim rsa pubkey e
    input[4 .. 8]                                                                                                       => email dkim rsa pubkey n len
    input[8 .. 8 + pubkey_n_len ]                                                                                       => email dkim rsa pubkey n
    input[8 + pubkey_n_len .. 12 + pubkey_n_len]                                                                        => email selector len
    input[12 + pubkey_n_len .. 12 + pubkey_n_len + selector_len]                                                        => email selector
    input[12 + pubkey_n_len + selector_len .. 16 + pubkey_n_len + selector_len]                                         => email sdid len
    input[16 + pubkey_n_len + selector_len .. 16 + pubkey_n_len + selector_len + sdid_len]                              => email sdid
    input[16 + pubkey_n_len + selector_len + sdid_len .. 20 + pubkey_n_len + selector_len + sdid_len]                   => email utf8 len
    input[20 + pubkey_n_len + selector_len + sdid_len .. 20 + pubkey_n_len + selector_len + sdid_len + email_len]       => email utf8 bytes
  
  ================
    output[]
 */
int email_parse(gw_context_t *ctx,
                const uint8_t *code_data,
                const size_t code_size,
                bool is_static_call,
                const uint8_t *input_src,
                const size_t input_size,
                uint8_t **output, size_t *output_size)
{
  ckb_debug("email prase start");
  uint8_t *mut_input_src = (uint8_t *)input_src;
  reverse_vec_n(mut_input_src, 4);
  uint32_t *pubkey_e = (uint32_t *)(mut_input_src);
  reverse_vec_n(mut_input_src + 4, 4);
  uint32_t *pubkey_n_size = (uint32_t *)(mut_input_src + 4);
  reverse_vec_n(mut_input_src + 8, *pubkey_n_size);
  uint8_t *pubkey_n = mut_input_src + 8;
  reverse_vec_n(mut_input_src + 8 + *pubkey_n_size, 4);
  uint32_t *selector_len = (uint32_t *)(mut_input_src + 8 + *pubkey_n_size);
  uint8_t *selector = (uint8_t *)(mut_input_src + 12 + *pubkey_n_size);
  reverse_vec_n(mut_input_src + 12 + *pubkey_n_size + *selector_len, 4);
  uint32_t *sdid_len = (uint32_t *)(mut_input_src + 12 + *pubkey_n_size + *selector_len);
  uint8_t *sdid = (uint8_t *)(mut_input_src + 16 + *pubkey_n_size + *selector_len);
  reverse_vec_n(mut_input_src + 16 + *pubkey_n_size + *selector_len + *sdid_len, 4);
  uint32_t *email_len = (uint32_t *)(mut_input_src + 16 + *pubkey_n_size + *selector_len + *sdid_len);
  uint8_t *raw_email = mut_input_src + 20 + *pubkey_n_size + *selector_len + *sdid_len;

  ckb_debug("input parse succeed");

  Email *email = NULL;
  int ret = 0;
  unsigned long from_header_len = 0;
  uint8_t *from_header = NULL;
  unsigned long subject_header_len = 0;
  uint8_t *subject_header = NULL;
  uint8_t *subject_header_bytes = NULL;
  const uint8_t *const *dkim_msg = NULL;
  const uintptr_t *dkim_msg_len = NULL;
  uintptr_t dkim_msg_num = 0;
  const uint8_t *const *dkim_sig = NULL;
  const uintptr_t *dkim_sig_len = NULL;
  const uint8_t *const *dkim_selector = NULL;
  const uintptr_t *dkim_selector_len = NULL;
  const uint8_t *const *dkim_sdid = NULL;
  const uintptr_t *dkim_sdid_len = NULL;
  uintptr_t dkim_sig_num = 0;

  bool dkim_verify = false;

  if (input_size != 4 + *email_len + 4 + 4 + *pubkey_n_size)
  {
    debug_print_int("input size", input_size);
    debug_print_int("email len", *email_len);
    debug_print_int("pubkey len", *pubkey_n_size);
    debug_print_data("input: ", input_src, input_size);
  }
  ret = get_email(raw_email, *email_len, &email);
  if (ret != 0)
  {
    goto end;
  }

  ret = get_email_dkim_msg(email, &dkim_msg, &dkim_msg_len, &dkim_msg_num);
  if (ret != 0)
  {
    goto end;
  }
  ret = get_email_dkim_sig(email,
                           &dkim_sig, &dkim_sig_len, &dkim_selector, &dkim_selector_len,
                           &dkim_sdid, &dkim_sdid_len, &dkim_sig_num);
  if (ret != 0)
  {
    goto end;
  }

  if (dkim_msg_num != dkim_sig_num)
  {
    ret = -3;
    goto end;
  }
  debug_print_data("pubkey n: ", pubkey_n, *pubkey_n_size);
  debug_print_int("pubkey n size: ", (uint32_t)(*pubkey_n_size));
  debug_print_int("pubkey e: ", *pubkey_e);
  debug_print_data("dkim msg: ", dkim_msg[0], dkim_msg_len[0]);
  debug_print_int("dkim msg len: ", dkim_msg_len[0]);
  debug_print_data("dkim sig: ", dkim_sig[0], dkim_sig_len[0]);
  debug_print_int("dkim sig len: ", dkim_sig_len[0]);
  for (uintptr_t i = 0; i < dkim_msg_num; i++)
  {
    if (*selector_len != *dkim_selector_len && memcmp(selector, dkim_selector, *selector_len) != 0)
    {
      break;
    }
    if (*sdid_len != *dkim_sdid_len && memcmp(sdid, dkim_sdid, *sdid_len) != 0)
    {
      break;
    }
    int r = internel_rsa_validate_signature(*pubkey_e, pubkey_n, (uint32_t)(*pubkey_n_size), CKB_MD_SHA256,
                                            (const uint8_t *)(dkim_msg[i]), (uint32_t)(dkim_msg_len[i]),
                                            (const uint8_t *)(dkim_sig[i]), (uint32_t)(dkim_sig_len[i]));
    if (r == 0)
    {
      dkim_verify = true;
      break;
    }
    debug_print_int("dkim verify ret: ", r);
  }
  if (!dkim_verify)
  {
    ret = -4;
    goto end;
  }

  ret = get_email_subject_header(email, &subject_header, &subject_header_len);
  debug_print_data("subject_header: ", subject_header, subject_header_len);
  debug_print_int("subject_header_len: ", subject_header_len);
  if (ret != 0)
  {
    goto end;
  }

  ret = get_email_from_header(email, &from_header, &from_header_len);
  debug_print_data("from_header: ", from_header, from_header_len);
  debug_print_int("from_header_len: ", from_header_len);
  if (ret != 0)
  {
    goto end;
  }

  uint8_t from_hash[32];
  SHA256_CTX hash_ctx_1;
  sha256_init(&hash_ctx_1);
  sha256_update(&hash_ctx_1, from_header, from_header_len - 1);
  sha256_final(&hash_ctx_1, from_hash);

  ret = deal_email_subject(subject_header, subject_header_len, &subject_header_bytes);
  debug_print_data("subject header bytes: ", subject_header_bytes, 32);
  if (ret != 0)
  {
    goto end;
  }

  *output = (uint8_t *)malloc(64);
  memcpy(*output, from_hash, 32);
  memcpy(*output + 32, subject_header_bytes, 32);
  *output_size = 64;

end:
  if (dkim_msg_num != 0)
  {
    for (uintptr_t i = 0; i < dkim_msg_num; i++)
    {
      rust_free_vec_u8((uint8_t *)(dkim_msg[i]), dkim_msg_len[i], dkim_msg_len[i]);
    }
    rust_free_ptr_vec((uint8_t **)dkim_msg, dkim_msg_num, dkim_msg_num);
    rust_free_vec_usize((uintptr_t *)dkim_msg_len, dkim_msg_num, dkim_msg_num);
  }
  if (dkim_sig_num != 0)
  {
    for (uintptr_t i = 0; i < dkim_sig_num; i++)
    {
      rust_free_vec_u8((uint8_t *)(dkim_sig[i]), dkim_sig_len[i], dkim_sig_len[i]);
      rust_free_vec_u8((uint8_t *)(dkim_selector[i]), dkim_selector_len[i], dkim_selector_len[i]);
      rust_free_vec_u8((uint8_t *)(dkim_sdid[i]), dkim_sdid_len[i], dkim_sdid_len[i]);
    }
    rust_free_ptr_vec((uint8_t **)dkim_sig, dkim_sig_num, dkim_sig_num);
    rust_free_ptr_vec((uint8_t **)dkim_selector, dkim_sig_num, dkim_sig_num);
    rust_free_ptr_vec((uint8_t **)dkim_sdid, dkim_sig_num, dkim_sig_num);
    rust_free_vec_usize((uintptr_t *)dkim_sig_len, dkim_sig_num, dkim_sig_num);
    rust_free_vec_usize((uintptr_t *)dkim_sdid, dkim_sig_num, dkim_sig_num);
    rust_free_vec_usize((uintptr_t *)dkim_sdid, dkim_sig_num, dkim_sig_num);
  }
  if (subject_header != NULL)
  {
    rust_free_vec_u8(subject_header, subject_header_len, subject_header_len);
  }
  if (from_header != NULL)
  {
    rust_free_vec_u8(from_header, from_header_len, from_header_len);
  }
  if (email != NULL)
  {
    drop_email(email);
  }
  if (subject_header_bytes != NULL)
  {
    free(subject_header_bytes);
  }
  debug_print_int("ret: ", ret);
  return ret;
}

int email_parse_gas(const uint8_t *input_src,
                    const size_t input_size,
                    uint64_t *gas)
{
  *gas = 3000;
  return 0;
}

bool match_precompiled_address(const evmc_address *destination,
                               precompiled_contract_gas_fn *contract_gas,
                               precompiled_contract_fn *contract)
{
  for (int i = 0; i < 19; i++)
  {
    if (destination->bytes[i] != 0)
    {
      return false;
    }
  }

  switch (destination->bytes[19])
  {
  case 1:
    *contract_gas = ecrecover_required_gas;
    *contract = ecrecover;
    break;
  case 2:
    *contract_gas = sha256hash_required_gas;
    *contract = sha256hash;
    break;
  case 3:
    *contract_gas = ripemd160hash_required_gas;
    *contract = ripemd160hash;
    break;
  case 4:
    *contract_gas = data_copy_required_gas;
    *contract = data_copy;
    break;
  case 5:
    *contract_gas = big_mod_exp_required_gas;
    *contract = big_mod_exp;
    break;
  case 6:
    *contract_gas = bn256_add_istanbul_gas;
    *contract = bn256_add_istanbul;
    break;
  case 7:
    *contract_gas = bn256_scalar_mul_istanbul_gas;
    *contract = bn256_scalar_mul_istanbul;
    break;
  case 8:
    *contract_gas = bn256_pairing_istanbul_gas;
    *contract = bn256_pairing_istanbul;
    break;
  case 9:
    *contract_gas = blake2f_required_gas;
    *contract = blake2f;
    break;
  case 0xf0:
    *contract_gas = balance_of_any_sudt_gas;
    *contract = balance_of_any_sudt;
    break;
  case 0xf1:
    *contract_gas = transfer_to_any_sudt_gas;
    *contract = transfer_to_any_sudt;
    break;
  case 0xf2:
    *contract_gas = recover_account_gas;
    *contract = recover_account;
    break;
  case 0xf3:
    *contract_gas = eth_to_godwoken_addr_gas;
    *contract = eth_to_godwoken_addr;
    break;
  case 0xf4:
    *contract_gas = rsa_validate_gas;
    *contract = rsa_validate_signature;
    break;
  case 0xf5:
    *contract_gas = email_parse_gas;
    *contract = email_parse;
    break;
  case 0xf6:
    *contract_gas = email_parse_gas;
    *contract = contract_get_email;
    break;
  case 0xf7:
    *contract_gas = email_parse_gas;
    *contract = email_get_dkim_sig_header;
    break;
  case 0xf8:
    *contract_gas = email_parse_gas;
    *contract = email_get_dkim_message_header;
    break;
  case 0xf9:
    *contract_gas = email_parse_gas;
    *contract = email_get_from_header;
    break;
  case 0xfa:
    *contract_gas = email_parse_gas;
    *contract = email_get_subject_header;
    break;
  default:
    *contract_gas = NULL;
    *contract = NULL;
    return false;
  }
  return true;
}

#endif /* #define CONTRACTS_H_ */
