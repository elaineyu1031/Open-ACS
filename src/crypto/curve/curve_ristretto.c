/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sodium.h>

#include "src/crypto/curve/curve.h"
#include "src/crypto/curve/curve_ristretto.h"
#include "sodium/crypto_core_ristretto255.h"

static enum curve_error scalar_random(unsigned char* r, size_t r_len) {
  if (r_len != crypto_core_ristretto255_SCALARBYTES) {
    return CURVE_BUFFER_LENGTH_ERROR;
  }
  crypto_core_ristretto255_scalar_random(r);
  return CURVE_SUCCESS;
}

static enum curve_error scalar_add(
    unsigned char* z,
    size_t z_len,
    const unsigned char* x,
    size_t x_len,
    const unsigned char* y,
    size_t y_len) {
  if (z_len != crypto_core_ristretto255_SCALARBYTES ||
      x_len != crypto_core_ristretto255_SCALARBYTES ||
      y_len != crypto_core_ristretto255_SCALARBYTES) {
    return CURVE_BUFFER_LENGTH_ERROR;
  }
  crypto_core_ristretto255_scalar_add(z, x, y);
  return CURVE_SUCCESS;
}

static enum curve_error scalar_sub(
    unsigned char* z,
    size_t z_len,
    const unsigned char* x,
    size_t x_len,
    const unsigned char* y,
    size_t y_len) {
  if (z_len != crypto_core_ristretto255_SCALARBYTES ||
      x_len != crypto_core_ristretto255_SCALARBYTES ||
      y_len != crypto_core_ristretto255_SCALARBYTES) {
    return CURVE_BUFFER_LENGTH_ERROR;
  }
  crypto_core_ristretto255_scalar_sub(z, x, y);
  return CURVE_SUCCESS;
}

static enum curve_error scalar_mult(
    unsigned char* z,
    size_t z_len,
    const unsigned char* x,
    size_t x_len,
    const unsigned char* y,
    size_t y_len) {
  if (z_len != crypto_core_ristretto255_SCALARBYTES ||
      x_len != crypto_core_ristretto255_SCALARBYTES ||
      y_len != crypto_core_ristretto255_SCALARBYTES) {
    return CURVE_BUFFER_LENGTH_ERROR;
  }
  crypto_core_ristretto255_scalar_mul(z, x, y);
  return CURVE_SUCCESS;
}

static enum curve_error scalar_inv(
    unsigned char* r,
    size_t r_len,
    const unsigned char* s,
    size_t s_len) {
  if (r_len != crypto_core_ristretto255_SCALARBYTES ||
      s_len != crypto_core_ristretto255_SCALARBYTES) {
    return CURVE_BUFFER_LENGTH_ERROR;
  }
  return crypto_core_ristretto255_scalar_invert(r, s) ? CURVE_INVALID_INPUT
                                                      : CURVE_SUCCESS;
}

static enum curve_error group_add(
    unsigned char* r,
    size_t r_len,
    const unsigned char* p,
    size_t p_len,
    const unsigned char* q,
    size_t q_len) {
  if (r_len != crypto_core_ristretto255_BYTES ||
      p_len != crypto_core_ristretto255_BYTES ||
      q_len != crypto_core_ristretto255_BYTES) {
    return CURVE_BUFFER_LENGTH_ERROR;
  }
  return crypto_core_ristretto255_add(r, p, q) ? CURVE_INVALID_INPUT
                                               : CURVE_SUCCESS;
}

static enum curve_error group_sub(
    unsigned char* r,
    size_t r_len,
    const unsigned char* p,
    size_t p_len,
    const unsigned char* q,
    size_t q_len) {
  if (r_len != crypto_core_ristretto255_BYTES ||
      p_len != crypto_core_ristretto255_BYTES ||
      q_len != crypto_core_ristretto255_BYTES) {
    return CURVE_BUFFER_LENGTH_ERROR;
  }
  return crypto_core_ristretto255_sub(r, p, q) ? CURVE_INVALID_INPUT
                                               : CURVE_SUCCESS;
}

static enum curve_error group_exp(
    unsigned char* q,
    size_t q_len,
    const unsigned char* n,
    size_t n_len,
    const unsigned char* p,
    size_t p_len) {
  if (q_len != crypto_core_ristretto255_BYTES ||
      n_len != crypto_core_ristretto255_SCALARBYTES ||
      p_len != crypto_core_ristretto255_BYTES) {
    return CURVE_BUFFER_LENGTH_ERROR;
  }
  return crypto_scalarmult_ristretto255(q, n, p) ? CURVE_INVALID_INPUT
                                                 : CURVE_SUCCESS;
}

static enum curve_error group_exp_generator(
    unsigned char* q,
    size_t q_len,
    const unsigned char* n,
    size_t n_len) {
  if (q_len != crypto_core_ristretto255_BYTES ||
      n_len != crypto_core_ristretto255_SCALARBYTES) {
    return CURVE_BUFFER_LENGTH_ERROR;
  }
  return crypto_scalarmult_ristretto255_base(q, n) ? CURVE_INVALID_INPUT
                                                   : CURVE_SUCCESS;
}

static enum curve_error check_on_curve(const unsigned char* p, size_t p_len) {
  if (p_len != crypto_core_ristretto255_BYTES) {
    return CURVE_BUFFER_LENGTH_ERROR;
  }
  return crypto_core_ristretto255_is_valid_point(p) ? CURVE_SUCCESS
                                                    : CURVE_NOT_ON_CURVE;
}

static enum curve_error hash_to_scalar(
    unsigned char* result,
    const unsigned char** buf_arr,
    const size_t* buf_len,
    int n_buf) {
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512_state state;
  if (crypto_hash_sha512_init(&state)) {
    return CURVE_HASH_ERROR;
  };
  for (int i = 0; i < n_buf; ++i) {
    if (crypto_hash_sha512_update(&state, buf_arr[i], buf_len[i])) {
      return CURVE_HASH_ERROR;
    }
  }
  if (crypto_hash_sha512_final(&state, hash)) {
    return CURVE_HASH_ERROR;
  }

  // Reduce to scalar
  crypto_core_ristretto255_scalar_reduce(result, hash);
  return CURVE_SUCCESS;
}

static enum curve_error hash_to_curve(
    unsigned char* result,
    const unsigned char** buf_arr,
    const size_t* buf_len,
    int n_buf) {
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512_state state;
  if (crypto_hash_sha512_init(&state)) {
    return CURVE_HASH_ERROR;
  }
  for (int i = 0; i < n_buf; ++i) {
    if (crypto_hash_sha512_update(&state, buf_arr[i], buf_len[i])) {
      return CURVE_HASH_ERROR;
    }
  }
  if (crypto_hash_sha512_final(&state, hash)) {
    return CURVE_HASH_ERROR;
  }
  if (crypto_core_ristretto255_from_hash(result, hash)) {
    return CURVE_HASH_ERROR;
  }
  return CURVE_SUCCESS;
}

static enum curve_error get_generator(unsigned char* g, size_t g_len) {
  if (g_len != crypto_core_ristretto255_BYTES) {
    return CURVE_BUFFER_LENGTH_ERROR;
  }
  // We get generator g by computing g^1
  // Create a scalar 1 with little endian
  static const unsigned char one[crypto_scalarmult_curve25519_SCALARBYTES] = {
      0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
  return crypto_scalarmult_ristretto255_base(g, one);
}

void curve_ristretto_init(curve_t* curve) {
  curve->scalar_bytes = crypto_core_ristretto255_SCALARBYTES;
  curve->element_bytes = crypto_core_ristretto255_BYTES;
  curve->scalar_random = scalar_random;
  curve->scalar_add = scalar_add;
  curve->scalar_sub = scalar_sub;
  curve->scalar_mult = scalar_mult;
  curve->scalar_inv = scalar_inv;
  curve->group_op = group_add;
  curve->group_inv_op = group_sub;
  curve->group_exp = group_exp;
  curve->group_exp_generator = group_exp_generator;
  curve->check_on_curve = check_on_curve;
  curve->hash_to_scalar = hash_to_scalar;
  curve->hash_to_curve = hash_to_curve;
  curve->get_generator = get_generator;
}
