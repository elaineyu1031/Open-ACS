/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sodium.h>

#include "src/crypto/curve/curve.h"
#include "src/crypto/dleqproof/dleqproof.h"
#include "src/crypto/voprf/voprf_exp_twohashdh.h"
#include "src/crypto/voprf/voprf_twohashdh.h"

#define CURVE_SUCCESS_CHECK(EXP)        \
  if (EXP != CURVE_SUCCESS) {           \
    return VOPRF_CURVE_OPERATION_ERROR; \
  }

static enum voprf_error blind(
    struct voprf* voprf,
    unsigned char* blinded_element,
    size_t blinded_element_len,
    unsigned char* blinding_factor,
    size_t blinding_factor_len,
    const unsigned char* input,
    size_t input_len) {
  size_t element_bytes = voprf->curve->element_bytes;
  size_t scalar_bytes = voprf->curve->scalar_bytes;
  if (blinded_element_len != element_bytes ||
      blinding_factor_len != scalar_bytes) {
    return VOPRF_BUFFER_LENGTH_ERROR;
  }

  // Sample random blinding factor
  CURVE_SUCCESS_CHECK(
      voprf->curve->scalar_random(blinding_factor, blinding_factor_len));

  unsigned char hashed_message_point[element_bytes];

  // Hash and blind input
  CURVE_SUCCESS_CHECK(voprf->curve->hash_to_curve(
      hashed_message_point,
      (const unsigned char*[]){input},
      (const size_t[]){input_len},
      1));
  CURVE_SUCCESS_CHECK(voprf->curve->group_exp(
      blinded_element,
      blinded_element_len,
      blinding_factor,
      blinded_element_len,
      hashed_message_point,
      element_bytes));
  return VOPRF_SUCCESS;
}

static enum voprf_error verifiable_unblind(
    struct voprf* voprf,
    unsigned char* unblinded_element,
    size_t unblinded_element_len,
    const unsigned char* proof_c,
    size_t proof_c_len,
    const unsigned char* proof_s,
    size_t proof_s_len,
    const unsigned char* blinding_factor,
    size_t blinding_factor_len,
    const unsigned char* evaluated_element,
    size_t evaluated_element_len,
    const unsigned char* blinded_element,
    size_t blinded_element_len,
    const unsigned char* pk,
    size_t pk_len,
    int flag_proof_verify) {
  size_t element_bytes = voprf->curve->element_bytes;
  size_t scalar_bytes = voprf->curve->scalar_bytes;
  if (unblinded_element_len != element_bytes ||
      blinding_factor_len != scalar_bytes ||
      evaluated_element_len != element_bytes ||
      blinded_element_len != element_bytes) {
    return VOPRF_BUFFER_LENGTH_ERROR;
  }
  CURVE_SUCCESS_CHECK(
      voprf->curve->check_on_curve(evaluated_element, evaluated_element_len));
  CURVE_SUCCESS_CHECK(
      voprf->curve->check_on_curve(blinded_element, blinded_element_len));

  // Verify proof
  if (flag_proof_verify) {
    if (proof_c == NULL || proof_s == NULL) {
      return VOPRF_PROOF_ERROR;
    }
    if (proof_c_len != scalar_bytes || proof_s_len != scalar_bytes ||
        pk_len != element_bytes) {
      return VOPRF_BUFFER_LENGTH_ERROR;
    }

    const size_t generator_len = voprf->curve->element_bytes;
    unsigned char generator[generator_len];
    CURVE_SUCCESS_CHECK(voprf->curve->get_generator(generator, generator_len));
    dleqproof_protocol_t dleqproof;
    dleqproof_init(&dleqproof, voprf->curve);
    if (dleqproof.verify(
            &dleqproof,
            proof_c,
            proof_c_len,
            proof_s,
            proof_s_len,
            generator,
            generator_len,
            blinded_element,
            blinded_element_len,
            pk,
            pk_len,
            evaluated_element,
            evaluated_element_len) != DLEQPROOF_SUCCESS) {
      return VOPRF_PROOF_ERROR;
    }
  }

  // Unblind evaluation
  unsigned char inv_blinding_factor[voprf->curve->scalar_bytes];

  CURVE_SUCCESS_CHECK(voprf->curve->scalar_inv(
      inv_blinding_factor, scalar_bytes, blinding_factor, blinding_factor_len));
  CURVE_SUCCESS_CHECK(voprf->curve->group_exp(
      unblinded_element,
      unblinded_element_len,
      inv_blinding_factor,
      scalar_bytes,
      evaluated_element,
      evaluated_element_len));
  return VOPRF_SUCCESS;
}

void voprf_exp_twohashdh_init(voprf_t* voprf, curve_t* curve) {
  voprf->final_evaluation_bytes = crypto_hash_sha512_BYTES;
  voprf->curve = curve;
  voprf->setup = setup;
  voprf->blind = blind;
  voprf->evaluate = evaluate;
  voprf->verifiable_unblind = verifiable_unblind;
  voprf->client_finalize = client_finalize;
  voprf->server_finalize = server_finalize;
}
