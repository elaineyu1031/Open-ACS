/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sodium.h>

#include "src/crypto/curve/curve.h"
#include "src/crypto/dleqproof/dleqproof.h"

#define CURVE_SUCCESS_CHECK(EXP)            \
  if (EXP != CURVE_SUCCESS) {               \
    return DLEQPROOF_CURVE_OPERATION_ERROR; \
  }

static enum dleqproof_error dleqproof_generate_proof_hash_challenge(
    curve_t* curve,
    unsigned char* proof_hash_challenge,
    size_t proof_hash_challenge_len,
    const unsigned char* base1,
    size_t base1_len,
    const unsigned char* base2,
    size_t base2_len,
    const unsigned char* element1,
    size_t element1_len,
    const unsigned char* element2,
    size_t element2_len,
    const unsigned char* r_base1,
    size_t r_base1_len,
    const unsigned char* r_base2,
    size_t r_base2_len) {
  size_t element_bytes = curve->element_bytes;
  size_t scalar_bytes = curve->scalar_bytes;
  if (proof_hash_challenge_len != scalar_bytes || base1_len != element_bytes ||
      base2_len != element_bytes || element1_len != element_bytes ||
      element2_len != element_bytes || r_base1_len != element_bytes ||
      r_base2_len != element_bytes) {
    return DLEQPROOF_BUFFER_LENGTH_ERROR;
  }

  CURVE_SUCCESS_CHECK(curve->hash_to_scalar(
      proof_hash_challenge, /* result */
      (const unsigned char*[]){
          base1, element1, base2, element2, r_base1, r_base2}, /* buf_arr */
      (const size_t[]){
          element_bytes,
          element_bytes,
          element_bytes,
          element_bytes,
          element_bytes,
          element_bytes}, /* buf_len */
      6 /* n_buf */));
  return DLEQPROOF_SUCCESS;
}

static enum dleqproof_error dleqproof_prove(
    dleqproof_protocol_t* protocol,
    unsigned char* proof_c,
    size_t proof_c_len,
    unsigned char* proof_s,
    size_t proof_s_len,
    const unsigned char* base1,
    size_t base1_len,
    const unsigned char* base2,
    size_t base2_len,
    const unsigned char* element1,
    size_t element1_len,
    const unsigned char* element2,
    size_t element2_len,
    const unsigned char* discrete_log,
    size_t discrete_log_len) {
  size_t element_bytes = protocol->curve->element_bytes;
  size_t scalar_bytes = protocol->curve->scalar_bytes;

  if (proof_c_len != scalar_bytes || proof_s_len != scalar_bytes ||
      base1_len != element_bytes || base2_len != element_bytes ||
      element1_len != element_bytes || element2_len != element_bytes ||
      discrete_log_len != scalar_bytes) {
    return DLEQPROOF_BUFFER_LENGTH_ERROR;
  }

  // Sample a random scalar r
  unsigned char r[scalar_bytes];
  CURVE_SUCCESS_CHECK(protocol->curve->scalar_random(r, scalar_bytes));

  // Compute base1 ^ r
  unsigned char r_base1[element_bytes];
  CURVE_SUCCESS_CHECK(protocol->curve->group_exp(
      r_base1, element_bytes, r, scalar_bytes, base1, element_bytes));

  // Compute base2 ^ r
  unsigned char r_base2[element_bytes];
  CURVE_SUCCESS_CHECK(protocol->curve->group_exp(
      r_base2, element_bytes, r, scalar_bytes, base2, element_bytes));

  // Compute hash challenge
  enum dleqproof_error generate_proof_hash_challenge_error =
      dleqproof_generate_proof_hash_challenge(
          protocol->curve,
          proof_c,
          proof_c_len,
          base1,
          base1_len,
          base2,
          base2_len,
          element1,
          element1_len,
          element2,
          element2_len,
          r_base1 /* base1^r */,
          element_bytes,
          r_base2 /* base2^r */,
          element_bytes);
  if (generate_proof_hash_challenge_error != DLEQPROOF_SUCCESS) {
    return generate_proof_hash_challenge_error;
  }

  // Compute challenge response: s <- (r - c * discreteLog)
  unsigned char tmp[scalar_bytes];
  CURVE_SUCCESS_CHECK(protocol->curve->scalar_mult(
      tmp, scalar_bytes, proof_c, scalar_bytes, discrete_log, scalar_bytes));
  CURVE_SUCCESS_CHECK(protocol->curve->scalar_sub(
      proof_s, scalar_bytes, r, scalar_bytes, tmp, scalar_bytes));
  return DLEQPROOF_SUCCESS;
}

static enum dleqproof_error dleqproof_verify(
    dleqproof_protocol_t* protocol,
    const unsigned char* proof_c,
    size_t proof_c_len,
    const unsigned char* proof_s,
    size_t proof_s_len,
    const unsigned char* base1,
    size_t base1_len,
    const unsigned char* base2,
    size_t base2_len,
    const unsigned char* element1,
    size_t element1_len,
    const unsigned char* element2,
    size_t element2_len) {
  size_t element_bytes = protocol->curve->element_bytes;
  size_t scalar_bytes = protocol->curve->scalar_bytes;

  if (proof_c_len != scalar_bytes || proof_s_len != scalar_bytes ||
      base1_len != element_bytes || base2_len != element_bytes ||
      element1_len != element_bytes || element2_len != element_bytes) {
    return DLEQPROOF_BUFFER_LENGTH_ERROR;
  }

  // Compute randomized bases:
  // r_base1 <- base1^s * element1^c
  // r_base2 <- base2^s * element2^c
  // we expect r_base1 = base1 ^ r, r_base2 = base2 ^ r
  unsigned char tmp_base_s1[element_bytes];
  unsigned char tmp_element_c1[element_bytes];
  unsigned char r_base1[element_bytes];
  unsigned char tmp_base_s2[element_bytes];
  unsigned char tmp_element_c2[element_bytes];
  unsigned char r_base2[element_bytes];

  CURVE_SUCCESS_CHECK(protocol->curve->group_exp(
      tmp_base_s1, element_bytes, proof_s, scalar_bytes, base1, element_bytes));

  CURVE_SUCCESS_CHECK(protocol->curve->group_exp(
      tmp_element_c1,
      element_bytes,
      proof_c,
      scalar_bytes,
      element1,
      element_bytes));
  CURVE_SUCCESS_CHECK(protocol->curve->group_op(
      r_base1,
      element_bytes,
      tmp_base_s1,
      element_bytes,
      tmp_element_c1,
      element_bytes));
  CURVE_SUCCESS_CHECK(protocol->curve->group_exp(
      tmp_base_s2, element_bytes, proof_s, scalar_bytes, base2, element_bytes));
  CURVE_SUCCESS_CHECK(protocol->curve->group_exp(
      tmp_element_c2,
      element_bytes,
      proof_c,
      scalar_bytes,
      element2,
      element_bytes));
  CURVE_SUCCESS_CHECK(protocol->curve->group_op(
      r_base2,
      element_bytes,
      tmp_base_s2,
      element_bytes,
      tmp_element_c2,
      element_bytes));
  // Compute hash challenge
  unsigned char c[scalar_bytes];
  enum dleqproof_error generate_proof_hash_challenge_error =
      dleqproof_generate_proof_hash_challenge(
          protocol->curve,
          c,
          scalar_bytes,
          base1,
          base1_len,
          base2,
          base2_len,
          element1,
          element1_len,
          element2,
          element2_len,
          r_base1,
          element_bytes,
          r_base2,
          element_bytes);
  if (generate_proof_hash_challenge_error != DLEQPROOF_SUCCESS) {
    return generate_proof_hash_challenge_error;
  }
  // Compare computed challenge with claimed proof challenge
  return sodium_memcmp(proof_c, c, scalar_bytes) ? DLEQPROOF_VERIFY_FAIL
                                                 : DLEQPROOF_SUCCESS;
}

void dleqproof_init(dleqproof_protocol_t* protocol, curve_t* curve) {
  protocol->curve = curve;
  protocol->prove = dleqproof_prove;
  protocol->verify = dleqproof_verify;
}
