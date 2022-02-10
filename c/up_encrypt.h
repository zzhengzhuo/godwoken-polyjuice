#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
typedef struct RustEmail Email;

#define SUCCESS 0

#define NULL_ERROR -1

#define NOT_VERIFY -2

#define UTF8_ERROR -3

#define EMAIL_PARSE_ERROR -4

#define STRING_CONVERT_ERROR -5

#define RSA_PUBKEY_ERROR -6

/**
 * # Safety
 *
 * This function is not safe.
 */
int32_t get_email(const uint8_t *input, uintptr_t input_len, Email **email);

/**
 * # Safety
 *
 * This function is not safe.
 */
void drop_email(Email *email);

/**
 * # Safety
 *
 * This function should not be called before the horsemen are ready.
 */
int32_t get_header_value(const Email *email,
                         const uint8_t *header,
                         uintptr_t header_len,
                         uint8_t **res,
                         uintptr_t *res_len);

int32_t get_body(const Email *email, uint8_t **res, uintptr_t *res_len);

/**
 * # Safety
 *
 * This function is not safe.
 */
int32_t get_email_from_header(const Email *email, uint8_t **from, uintptr_t *from_len);

/**
 * # Safety
 *
 * This function is not safe.
 */
int32_t get_email_subject_header(const Email *email, uint8_t **subject, uintptr_t *subject_len);

int32_t get_email_dkim_msg(const Email *email,
                           const uint8_t *const **dkim_msg,
                           const uintptr_t **dkim_msg_len,
                           uintptr_t *dkim_msg_num);

int32_t get_email_dkim_sig(const Email *email,
                           const uint8_t *const **dkim_sig,
                           const uintptr_t **dkim_sig_len,
                           uintptr_t *dkim_sig_num);

void rust_free_vec_u8(uint8_t *ptr, uintptr_t len, uintptr_t cap);

void rust_free_vec_usize(uintptr_t *ptr, uintptr_t len, uintptr_t cap);

void rust_free_ptr_vec(uint8_t **ptr, uintptr_t len, uintptr_t cap);
