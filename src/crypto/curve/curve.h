/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <stddef.h>

enum curve_error {
  CURVE_SUCCESS = 0,
  CURVE_UNKNOWN_ERROR = -1,
  CURVE_BUFFER_LENGTH_ERROR = 1,
  CURVE_INVALID_INPUT = 2,
  CURVE_NOT_ON_CURVE = 3,
  CURVE_HASH_ERROR = 4
};

/**
 * An interface for elliptic curve operations.
 *
 * The interface is designed for easy linking its function pointer members to
 * libsodium lib functions, although creating an implementation without
 * libsodium is possible. We also implement additional functions:
 * hash_to_scalar, hash_to_curve, get_generator, get_scalar_bytes, and
 * get_element_bytes for each curve.
 *
 * Default implementation for CURVE_ED25519 and CURVE_RISTRETTO is provided with
 * VOPRF lib.
 */

typedef struct curve {
  /**
   * A curve is defined on finite field F_Q over a prime order Q. Choose an
   * Elliptic curve E and define a group E(F_Q) over the F_Q-rational points on
   * E. Choose a base point g in E(F_Q), which generates a cyclic subgroup of
   * E(F_Q) whose order is a prime L. We call an element of finite field F_L a
   * "curve scalar", and an elements of group E(F_Q) a "curve element".
   * The curve struct uses unsigned char array to represent scalar and elements.
   *
   * The size of the curve scalar (length of unsigned char array).
   */
  size_t scalar_bytes;

  /**
   * The size of the curve elememt (length of unsigned char array).
   */
  size_t element_bytes;

  /**
   * ==== Scalar arithmetics over finite field F_L ====
   *
   * Fills r with a scalar_bytes representation of the scalar in {1, 2, ...,L-1}
   *
   * @param r A mutable unsigned char buffer to store the result.
   * @param r_len The size of buffer r. r_len should be scalar_bytes of the
   * curve.
   */
  enum curve_error (*scalar_random)(unsigned char* /* r */, size_t /* r_len */);

  /**
   * Computes x + y (mod L), and stores the result into z.
   *
   * @param z A mutable unsigned char buffer to store the result.
   * @param z_len The size of buffer z. z_len should be scalar_bytes of the
   * curve.
   * @param x Input scalar
   * @param x_len The size of buffer x. x_len should be scalar_bytes of the
   * curve.
   * @param y Input scalar
   * @param y_len The size of buffer y. y_len should be scalar_bytes of the
   * curve.
   */
  enum curve_error (*scalar_add)(
      unsigned char* /* z */,
      size_t /* z_len */,
      const unsigned char* /* x */,
      size_t /* x_len */,
      const unsigned char* /* y */,
      size_t /* y_len */);

  /**
   * Computes x - y (mod L), and stores the result into z.
   *
   * @param z A mutable unsigned char buffer to store the result.
   * @param z_len The size of buffer z. z_len should be scalar_bytes of the
   * curve.
   * @param x Input scalar
   * @param x_len The size of buffer x. x_len should be scalar_bytes of the
   * curve.
   * @param y Input scalar
   * @param y_len The size of buffer y. y_len should be scalar_bytes of the
   * curve.
   */
  enum curve_error (*scalar_sub)(
      unsigned char* /* z */,
      size_t /* z_len */,
      const unsigned char* /* x */,
      size_t /* x_len */,
      const unsigned char* /* y */,
      size_t /* y_len */);

  /**
   * Computes x * y (mod L), and stores the result into z.
   *
   * @param z A mutable unsigned char buffer to store the result.
   * @param z_len The size of buffer z. z_len should be scalar_bytes of the
   * curve.
   * @param x Input scalar
   * @param x_len The size of buffer x. x_len should be scalar_bytes of the
   * curve.
   * @param y Input scalar
   * @param y_len The size of buffer y. y_len should be scalar_bytes of the
   * curve.
   */
  enum curve_error (*scalar_mult)(
      unsigned char* /* z */,
      size_t /* z_len */,
      const unsigned char* /* x */,
      size_t /* x_len */,
      const unsigned char* /* y */,
      size_t /* y_len */);

  /**
   * Computes the multiplicative inverse of s (over L), and stores the result
   * into r.
   *
   * @param r A mutable unsigned char buffer to store the result.
   * @param r_len The size of buffer r. r_len should be scalar_bytes of the
   * curve.
   * @param s Input scalar
   * @param s_len The size of buffer s. s_len should be scalar_bytes of the
   * curve.
   * @return CURVE_INVALID_INPUT if s = 0
   */
  enum curve_error (*scalar_inv)(
      unsigned char* /* r */,
      size_t /* r_len */,
      const unsigned char* /* s */,
      size_t /* s_len */);

  /**
   * ==== Group operations over E(F_Q) ====
   *
   * Adds the element p to the element q, and stores the resulting element into
   * r. We use notation "*" for group operation: r = p * q
   *
   * @param r A mutable unsigned char buffer to store the result.
   * @param r_len The size of buffer r. r_len should be element_bytes of the
   * curve.
   * @param p Input element
   * @param p_len The size of buffer p. p_len should be element_bytes of the
   * curve.
   * @param q Input element
   * @param q_len The size of buffer q. q_len should be element_bytes of the
   * curve.
   * @return CURVE_INVALID_INPUT if p or q is not a valid curve element
   */
  enum curve_error (*group_op)(
      unsigned char* /* r */,
      size_t /* r_len */,
      const unsigned char* /* p */,
      size_t /* p_len */,
      const unsigned char* /* q */,
      size_t /* q_len */);

  /**
   * Subtracts the element p to the element q, and stores the resulting element
   * into r.
   *
   * @param r A mutable unsigned char buffer to store the result.
   * @param r_len The size of buffer r. r_len should be element_bytes of the
   * curve.
   * @param p Input element
   * @param p_len The size of buffer p. p_len should be element_bytes of the
   * curve.
   * @param q Input element
   * @param q_len The size of buffer q. q_len should be element_bytes of the
   * curve.
   * @return CURVE_INVALID_INPUT if p or q is not a valid curve element
   */
  enum curve_error (*group_inv_op)(
      unsigned char* /* r */,
      size_t /* r_len */,
      const unsigned char* /* p */,
      size_t /* p_len */,
      const unsigned char* /* q */,
      size_t /* q_len */);

  /**
   * Multiplies the element p by the scalar n, and stores the resulting element
   * into q. We use notation "^" for this operation: q = p ^ n.
   *
   * @param q A mutable unsigned char buffer to store the result.
   * @param q_len The size of buffer q. q_len should be element_bytes of the
   * curve.
   * @param n Input scalar
   * @param n_len The size of buffer n. n_len should be scalar_bytes of the
   * curve.
   * @param p Input element
   * @param p_len The size of buffer p. p_len should be element_bytes of the
   * curve.
   * @return CURVE_INVALID_INPUT if p is not a valid curve element, or the
   * result q is identity element
   */
  enum curve_error (*group_exp)(
      unsigned char* /* q */,
      size_t /* q_len */,
      const unsigned char* /* n */,
      size_t /* n_len */,
      const unsigned char* /* p */,
      size_t /* p_len */);

  /**
   * Multiplies the generator g by the scalar n, and stores the resulting
   * element into q. We use notation "^" for this operation: q = g ^ n.
   *
   * @param q A mutable unsigned char buffer to store the result.
   * @param q_len The size of buffer q. q_len should be element_bytes of the
   * curve.
   * @param n Input scalar
   * @param n_len The size of buffer n. n_len should be scalar_bytes of the
   * curve.
   * @return CURVE_INVALID_INPUT if the result q is identity element
   */
  enum curve_error (*group_exp_generator)(
      unsigned char* /* q */,
      size_t /* q_len */,
      const unsigned char* /* n */,
      size_t /* n_len */);

  /**
   * Encoded element validation
   * Checks if p is a valid curve element or not.
   *
   * @param p Input element
   * @param p_len The size of buffer p. p_len should be element_bytes of the
   * curve.
   * @return CURVE_SUCCESS on success, and CURVE_NOT_ON_CURVE if the check
   * fails.
   */
  enum curve_error (
      *check_on_curve)(const unsigned char* /* p */, size_t /* p_len */);

  /**
   * Hashes n_buf input bytes, reduces the hash result to a curve scalar, and
   * stores the resulting scalar into `result`
   *
   * @param result A mutable unsigned char buffer to store the result. The size
   * of the buffer should be scalar_bytes of the curve.
   * @param buf_arr A pointer to an array, storing pointers to unsigned char
   * buffers. The size of the array should be n_buf, i.e. there should be n_buf
   * unsigned char buffers.
   * @param buf_len A pointer to an array, storing the length of the unsigned
   * char buffer corresponding to the same index of buf_arr. The size of the
   * array should be n_buf, i.e. there should be n_buf lengths.
   * @param n_buf Number of input buffers
   */
  enum curve_error (*hash_to_scalar)(
      unsigned char* /* result */,
      const unsigned char** /* buf_arr */,
      const size_t* /* buf_len */,
      int /* n_buf */);

  /**
   * Hashes n_buf input bytes, maps the hash result to a curve element, and
   * stores the resulting element into `result`
   *
   * @param result A mutable unsigned char buffer to store the result. The size
   * of the buffer should be element_bytes of the curve.
   * @param buf_arr A pointer to an array, storing pointers to unsigned char
   * buffers. The size of the array should be n_buf, i.e. there should be n_buf
   * unsigned char buffers.
   * @param buf_len A pointer to an array, storing the length of the unsigned
   * char buffer corresponding to the same index of buf_arr. The size of the
   * array should be n_buf, i.e. there should be n_buf lengths.
   * @param n_buf Number of input buffers
   */
  enum curve_error (*hash_to_curve)(
      unsigned char* /* result */,
      const unsigned char** /* buf_arr */,
      const size_t* /* buf_len */,
      int /* n_buf */);

  /**
   * Get the generator of the curve. This function will always get the same
   * result.
   *
   * @param g A mutable unsigned char buffer to store the result.
   * @param g_len The size of buffer g. g_len should be element_bytes of the
   * curve.
   */
  enum curve_error (*get_generator)(unsigned char* /* g */, size_t /* g_len */);

} curve_t;
