#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

static const int32_t SUCCESS = 0;

static const int32_t NULL_ERROR = -1;

static const int32_t NOT_VERIFY = -2;

static const int32_t UTF8_ERROR = -3;

static const int32_t EMAIL_PARSE_ERROR = -4;

static const int32_t STRING_CONVERT_ERROR = -5;

static const int32_t RSA_PUBKEY_ERROR = -6;

extern "C" {

int32_t email_verify(const uint8_t *email_s,
                     uintptr_t email_s_len,
                     uint32_t e,
                     const uint8_t *n,
                     uintptr_t n_len,
                     uint8_t **subject,
                     uintptr_t *subject_len,
                     uint8_t **from,
                     uintptr_t *from_len);

int32_t rsa_with_sha256_verify(uint32_t e,
                               const uint8_t *n,
                               uintptr_t n_len,
                               const uint8_t *message,
                               uintptr_t message_len,
                               const uint8_t *signature,
                               uintptr_t signature_len);

} // extern "C"
