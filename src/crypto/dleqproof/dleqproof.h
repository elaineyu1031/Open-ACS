/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <stddef.h>

#include "src/crypto/curve/curve.h"

enum dleqproof_error {
  DLEQPROOF_SUCCESS = 0,
  DLEQPROOF_UNKNOWN_ERROR = -1,
  DLEQPROOF_BUFFER_LENGTH_ERROR = 1,
  DLEQPROOF_CURVE_OPERATION_ERROR = 2,
  DLEQPROOF_VERIFY_FAIL = 3,
};

/**
 * An interface for DLEQPROOF protocol.
 *
 * Discrete log equivalence proof (DLEQ proof)
 * A DLEQ proof allows the server to prove to the client that the pairs
 * (element1, base1) and (element2, base2) have the same discrete log relation x
 * (i.e. element1 = base1 ^ x, element2 = base2 ^ x) without release x to the
 * client.
 *
 * A default implementation is provided.
 */

typedef struct dleqproof_protocol dleqproof_protocol_t;

struct dleqproof_protocol {
  /**
   * The elliptic curve used in this dleqproof protocol.
   */
  curve_t* curve;

  /**
   * Computes proof from base1, base2, element1, element2, discrete_log.
   * proof_c = hash(base1, base2, element1, element2, base1 ^ r, base2 ^ r)
   * proof_s = r - proof_c * discrete_log
   * where r is random generated scalar.
   *
   * @param protocol A pointer to dleqproof_protocol struct.
   * @param proof_c Mutable unsigned char buffer for output.
   * @param proof_c_len The size of this buffer should be scalar_bytes of the
   * curve.
   * @param proof_s Mutable unsigned char buffer for output.
   * @param proof_s_len The size of this buffer should be scalar_bytes of the
   * curve.
   * @param base1 Input element
   * @param base1_len The size of this buffer should be element_bytes of the
   * curve.
   * @param base2 Input element
   * @param base2_len The size of this buffer should be element_bytes of the
   * curve.
   * @param element1 Input element
   * @param element1_len The size of this buffer should be element_bytes of the
   * curve.
   * @param element2 Input element
   * @param element2_len The size of this buffer should be element_bytes of the
   * curve.
   * @param discrete_log Input scalar
   * @param discrete_log_len The size of this buffer should be scalar_bytes of
   * the curve.
   * @return DLEQPROOF_SUCCESS on success. DLEQPROOF_ERROR if there are
   * .       curve errors.
   */

  enum dleqproof_error (*prove)(
      dleqproof_protocol_t* /* protocol */,
      unsigned char* /* proof_c */,
      size_t /* proof_c_len */,
      unsigned char* /* proof_s */,
      size_t /* proof_s_len */,
      const unsigned char* /* base1 */,
      size_t /* base1_len */,
      const unsigned char* /* base2 */,
      size_t /* base2_len */,
      const unsigned char* /* element1 */,
      size_t /* element1_len */,
      const unsigned char* /* element2 */,
      size_t /* element2_len */,
      const unsigned char* /* discrete_log */,
      size_t /* discrete_log_len */);

  /**
   * Verify proof with base1, base2, element1, element2.
   *
   * @param protocol A pointer to dleqproof_protocol struct.
   * @param proof_c Input scalar
   * @param proof_c_len The size of this buffer should be scalar_bytes of the
   * curve.
   * @param proof_s Input scalar
   * @param proof_s_len The size of this buffer should be scalar_bytes of the
   * curve.
   * @param base1 Input element
   * @param base1_len The size of this buffer should be element_bytes of the
   * curve.
   * @param base2 Input element
   * @param base2_len The size of this buffer should be element_bytes of the
   * curve.
   * @param element1 Input element
   * @param element1_len The size of this buffer should be element_bytes of the
   * curve.
   * @param element2 Input element
   * @param element2_len The size of this buffer should be element_bytes of the
   * curve.
   * @return DLEQPROOF_SUCCESS on success, DLEQPROOF_FAIL if verification fails.
   *         DLEQPROOF_ERROR if there are curve errors.
   */
  enum dleqproof_error (*verify)(
      dleqproof_protocol_t* /* protocol */,
      const unsigned char* /* proof_c */,
      size_t /* proof_c_len */,
      const unsigned char* /* proof_s */,
      size_t /* proof_s_len */,
      const unsigned char* /* base1 */,
      size_t /* base1_len */,
      const unsigned char* /* base2 */,
      size_t /* base2_len */,
      const unsigned char* /* element1 */,
      size_t /* element1_len */,
      const unsigned char* /* element2 */,
      size_t /* element2_len */);
};

/**
 * A default dleqproof_protocal implementation.
 * Example with curve ed25519:
 *   curve_t c;
 *   dleqproof_protocol_t p;
 *   curve_ed25519_init(&c);
 *   dleqproof_init(&p, &c);
 *   p.prove(&p, ...);
 */

void dleqproof_init(dleqproof_protocol_t* /* protocol */, curve_t* /* curve */);
