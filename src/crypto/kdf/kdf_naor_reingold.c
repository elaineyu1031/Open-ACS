/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sodium.h>
#include <string.h>

#include "src/crypto/curve/curve.h"
#include "src/crypto/dleqproof/dleqproof.h"
#include "src/crypto/kdf/kdf.h"
#include "src/crypto/kdf/kdf_naor_reingold.h"

#define NAOR_REINGOLD_ATTRIBUTE_BITS 8 * crypto_hash_sha256_BYTES

#define CURVE_SUCCESS_CHECK(EXP)      \
  if (EXP != CURVE_SUCCESS) {         \
    return KDF_CURVE_OPERATION_ERROR; \
  }

/**
 * Define structs for primary key cursors and helpers to initialize these
 * cursors.
 *
 * psk = a0 || a_vec_0 || a_vec_1 || ... || a_vec_255
 * ppk = h || p0 || h_vec_0 || h_vec_1 || ... || h_vec_255
 * primary_key = psk || ppk
 */

typedef struct {
  unsigned char* a0;
  unsigned char* a_vec;
} naor_reingold_primary_private_key_mutable_cursor;

typedef struct {
  unsigned char* h;
  unsigned char* p0;
  unsigned char* h_vec;
} naor_reingold_primary_public_key_mutable_cursor;

typedef struct {
  unsigned char* pi;
  unsigned char* p_vec;
} naor_reingold_public_key_proof_mutable_cursor;

typedef struct {
  const unsigned char* a0;
  const unsigned char* a_vec;
} naor_reingold_primary_private_key_cursor;

typedef struct {
  const unsigned char* h;
  const unsigned char* p0;
  const unsigned char* h_vec;
} naor_reingold_primary_public_key_cursor;

typedef struct {
  const unsigned char* pi;
  const unsigned char* p_vec;
} naor_reingold_public_key_proof_cursor;

static void init_primary_private_key_mutable_cursor(
    kdf_t* kdf,
    naor_reingold_primary_private_key_mutable_cursor* psk_cursor,
    unsigned char* psk) {
  psk_cursor->a0 = psk;
  psk_cursor->a_vec = psk + 1 * kdf->curve->scalar_bytes;
}

static void init_primary_public_key_mutable_cursor(
    kdf_t* kdf,
    naor_reingold_primary_public_key_mutable_cursor* ppk_cursor,
    unsigned char* ppk) {
  ppk_cursor->h = ppk;
  ppk_cursor->p0 = ppk + 1 * kdf->curve->element_bytes;
  ppk_cursor->h_vec = ppk + 2 * kdf->curve->element_bytes;
}

static void init_primary_key_mutable_cursor(
    kdf_t* kdf,
    naor_reingold_primary_private_key_mutable_cursor* psk_cursor,
    naor_reingold_primary_public_key_mutable_cursor* ppk_cursor,
    unsigned char* primary_key) {
  const size_t ppk_offset = kdf->primary_private_key_bytes;
  init_primary_private_key_mutable_cursor(kdf, psk_cursor, primary_key);
  init_primary_public_key_mutable_cursor(
      kdf, ppk_cursor, primary_key + ppk_offset);
}

static void init_public_key_proof_mutable_cursor(
    kdf_t* kdf,
    naor_reingold_public_key_proof_mutable_cursor* pk_proof_cursor,
    unsigned char* pk_proof) {
  pk_proof_cursor->pi = pk_proof;
  pk_proof_cursor->p_vec =
      pk_proof + NAOR_REINGOLD_ATTRIBUTE_BITS * 2 * kdf->curve->scalar_bytes;
}

static void init_primary_private_key_cursor(
    kdf_t* kdf,
    naor_reingold_primary_private_key_cursor* psk_cursor,
    const unsigned char* psk) {
  psk_cursor->a0 = psk;
  psk_cursor->a_vec = psk + 1 * kdf->curve->scalar_bytes;
}

static void init_primary_public_key_cursor(
    kdf_t* kdf,
    naor_reingold_primary_public_key_cursor* ppk_cursor,
    const unsigned char* ppk) {
  ppk_cursor->h = ppk;
  ppk_cursor->p0 = ppk + 1 * kdf->curve->element_bytes;
  ppk_cursor->h_vec = ppk + 2 * kdf->curve->element_bytes;
}

static void init_primary_key_cursor(
    kdf_t* kdf,
    naor_reingold_primary_private_key_cursor* psk_cursor,
    naor_reingold_primary_public_key_cursor* ppk_cursor,
    const unsigned char* primary_key) {
  const size_t ppk_offset = kdf->primary_private_key_bytes;
  init_primary_private_key_cursor(kdf, psk_cursor, primary_key);
  init_primary_public_key_cursor(kdf, ppk_cursor, primary_key + ppk_offset);
}

static void init_public_key_proof_cursor(
    kdf_t* kdf,
    naor_reingold_public_key_proof_cursor* pk_proof_cursor,
    const unsigned char* pk_proof) {
  pk_proof_cursor->pi = pk_proof;
  pk_proof_cursor->p_vec =
      pk_proof + NAOR_REINGOLD_ATTRIBUTE_BITS * 2 * kdf->curve->scalar_bytes;
}

static void hash_attributes(
    unsigned char* hash,
    int n_attributes,
    const unsigned char** attribute_arr,
    const size_t* attribute_len_arr) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  for (int i = 0; i < n_attributes; ++i) {
    crypto_hash_sha256_update(&state, attribute_arr[i], attribute_len_arr[i]);
  }
  crypto_hash_sha256_final(&state, hash);
}

static enum kdf_error generate_primary_key(
    kdf_t* kdf,
    unsigned char* primary_key,
    size_t primary_key_len) {
  size_t scalar_bytes = kdf->curve->scalar_bytes;
  size_t element_bytes = kdf->curve->element_bytes;
  if (primary_key_len != kdf->primary_key_bytes) {
    return KDF_BUFFER_LENGTH_ERROR;
  }
  naor_reingold_primary_private_key_mutable_cursor psk_cursor;
  naor_reingold_primary_public_key_mutable_cursor ppk_cursor;
  init_primary_key_mutable_cursor(kdf, &psk_cursor, &ppk_cursor, primary_key);

  unsigned char h_scalar[scalar_bytes];
  CURVE_SUCCESS_CHECK(kdf->curve->scalar_random(h_scalar, scalar_bytes));
  CURVE_SUCCESS_CHECK(kdf->curve->scalar_random(psk_cursor.a0, scalar_bytes));
  CURVE_SUCCESS_CHECK(kdf->curve->group_exp_generator(
      ppk_cursor.h, element_bytes, h_scalar, scalar_bytes));
  CURVE_SUCCESS_CHECK(kdf->curve->group_exp_generator(
      ppk_cursor.p0, element_bytes, psk_cursor.a0, scalar_bytes));

  for (int i = 0; i < NAOR_REINGOLD_ATTRIBUTE_BITS; ++i) {
    unsigned char* a_vec_i = psk_cursor.a_vec + i * scalar_bytes;
    unsigned char* h_vec_i = ppk_cursor.h_vec + i * element_bytes;
    CURVE_SUCCESS_CHECK(kdf->curve->scalar_random(a_vec_i, scalar_bytes));
    CURVE_SUCCESS_CHECK(kdf->curve->group_exp(
        h_vec_i,
        element_bytes,
        a_vec_i,
        scalar_bytes,
        ppk_cursor.h,
        element_bytes));
  }

  sodium_memzero(h_scalar, scalar_bytes);

  return KDF_SUCCESS;
}

static enum kdf_error derive_key_pair(
    kdf_t* kdf,
    unsigned char* sk,
    size_t sk_len,
    unsigned char* pk,
    size_t pk_len,
    unsigned char* pk_proof,
    size_t pk_proof_len,
    const unsigned char* primary_key,
    size_t primary_key_len,
    int n_attributes,
    const unsigned char** attribute_arr,
    const size_t* attribute_len_arr,
    int flag_pk_proof_generate) {
  const size_t scalar_bytes = kdf->curve->scalar_bytes;
  const size_t element_bytes = kdf->curve->element_bytes;

  if (sk_len != scalar_bytes || pk_len != element_bytes ||
      primary_key_len != kdf->primary_key_bytes) {
    return KDF_BUFFER_LENGTH_ERROR;
  }
  if (flag_pk_proof_generate) {
    if (pk_proof == NULL) {
      return KDF_PK_PROOF_ERROR;
    }
    if (pk_proof_len != kdf->public_key_proof_bytes) {
      return KDF_BUFFER_LENGTH_ERROR;
    }
  }

  naor_reingold_primary_private_key_cursor psk_cursor;
  naor_reingold_primary_public_key_cursor ppk_cursor;
  init_primary_key_cursor(kdf, &psk_cursor, &ppk_cursor, primary_key);

  naor_reingold_public_key_proof_mutable_cursor pk_proof_cursor;
  if (flag_pk_proof_generate) {
    sodium_memzero(pk_proof, element_bytes);
    init_public_key_proof_mutable_cursor(kdf, &pk_proof_cursor, pk_proof);
  }

  // Hash attributes
  unsigned char hash[crypto_hash_sha256_BYTES];
  hash_attributes(hash, n_attributes, attribute_arr, attribute_len_arr);

  // Generate attribute key
  unsigned char partial_sk_buf1[scalar_bytes];
  unsigned char partial_sk_buf2[scalar_bytes];
  unsigned char* curr_partial_sk = partial_sk_buf1;
  unsigned char* prev_partial_sk = partial_sk_buf2;
  memcpy(prev_partial_sk, psk_cursor.a0, scalar_bytes);

  unsigned char partial_pk_buf1[element_bytes];
  unsigned char partial_pk_buf2[element_bytes];
  unsigned char* curr_partial_pk = partial_pk_buf1;
  unsigned char* prev_partial_pk = partial_pk_buf2;
  memcpy(prev_partial_pk, ppk_cursor.p0, element_bytes);

  for (int i = 0; i < NAOR_REINGOLD_ATTRIBUTE_BITS; ++i) {
    // We use little endian on the bytes.
    // For every 8 bits, i.e. i = 8k ~ 8(k+1)-1, we will use the k-th ((i/8)-th)
    // byte of the hash result, and check the (i%8)-th bit from the right.
    const unsigned char byte = hash[i / 8];
    if (!(byte & (1 << (i % 8)))) {
      continue;
    }

    const unsigned char* a_vec_i = psk_cursor.a_vec + i * scalar_bytes;
    const unsigned char* h_vec_i = ppk_cursor.h_vec + i * element_bytes;

    CURVE_SUCCESS_CHECK(kdf->curve->scalar_mult(
        curr_partial_sk,
        scalar_bytes,
        prev_partial_sk,
        scalar_bytes,
        a_vec_i,
        scalar_bytes));
    CURVE_SUCCESS_CHECK(kdf->curve->group_exp(
        curr_partial_pk,
        element_bytes,
        a_vec_i,
        scalar_bytes,
        prev_partial_pk,
        element_bytes));

    if (flag_pk_proof_generate) {
      dleqproof_protocol_t dleqproof;
      dleqproof_init(&dleqproof, kdf->curve);
      if (dleqproof.prove(
              &dleqproof /* protocol */,
              pk_proof_cursor.pi + 2 * i * scalar_bytes /* proof_c */,
              scalar_bytes,
              pk_proof_cursor.pi + (2 * i + 1) * scalar_bytes /* proof_s */,
              scalar_bytes,
              ppk_cursor.h /* base1 */,
              element_bytes,
              prev_partial_pk /* base2 */,
              element_bytes,
              h_vec_i /* element1 */,
              element_bytes,
              curr_partial_pk /* element2 */,
              element_bytes,
              a_vec_i /* discrete_log */,
              scalar_bytes) != DLEQPROOF_SUCCESS) {
        return KDF_PK_PROOF_ERROR;
      }

      memcpy(
          pk_proof_cursor.p_vec + i * element_bytes,
          curr_partial_pk,
          element_bytes);
    }

    unsigned char* tmp;
    tmp = curr_partial_sk;
    curr_partial_sk = prev_partial_sk;
    prev_partial_sk = tmp;

    tmp = curr_partial_pk;
    curr_partial_pk = prev_partial_pk;
    prev_partial_pk = tmp;
  }

  memcpy(sk, prev_partial_sk, scalar_bytes);
  memcpy(pk, prev_partial_pk, element_bytes);
  sodium_memzero(partial_sk_buf1, scalar_bytes);
  sodium_memzero(partial_sk_buf2, scalar_bytes);

  return KDF_SUCCESS;
}

static enum kdf_error verify_public_key(
    kdf_t* kdf,
    const unsigned char* pk,
    size_t pk_len,
    const unsigned char* pk_proof,
    size_t pk_proof_len,
    const unsigned char* ppk,
    size_t ppk_len,
    int n_attributes,
    const unsigned char** attribute_arr,
    const size_t* attribute_len_arr) {
  size_t scalar_bytes = kdf->curve->scalar_bytes;
  size_t element_bytes = kdf->curve->element_bytes;
  if (pk_len != element_bytes || pk_proof_len != kdf->public_key_proof_bytes ||
      ppk_len != kdf->primary_public_key_bytes) {
    return KDF_BUFFER_LENGTH_ERROR;
  }

  naor_reingold_primary_public_key_cursor ppk_cursor;
  init_primary_public_key_cursor(kdf, &ppk_cursor, ppk);

  naor_reingold_public_key_proof_cursor pk_proof_cursor;
  init_public_key_proof_cursor(kdf, &pk_proof_cursor, pk_proof);

  // Hash attributes
  unsigned char hash[crypto_hash_sha256_BYTES];
  hash_attributes(hash, n_attributes, attribute_arr, attribute_len_arr);

  const unsigned char* prev_partial_pk = ppk_cursor.p0;
  for (int i = 0; i < NAOR_REINGOLD_ATTRIBUTE_BITS; ++i) {
    // We use little endian on the bytes.
    // For every 8 bits, i.e. i = 8k ~ 8(k+1)-1, we will use the k-th ((i/8)-th)
    // byte of the hash result, and check the (i%8)-th bit from the right.
    const unsigned char byte = hash[i / 8];
    if (!(byte & (1 << (i % 8)))) {
      continue;
    }
    dleqproof_protocol_t dleqproof;
    dleqproof_init(&dleqproof, kdf->curve);

    if (dleqproof.verify(
            &dleqproof /* protocol */,
            pk_proof_cursor.pi + 2 * i * scalar_bytes /* proof_c */,
            scalar_bytes,
            pk_proof_cursor.pi + (2 * i + 1) * scalar_bytes /* proof_s */,
            scalar_bytes,
            ppk_cursor.h /* base1 */,
            element_bytes,
            prev_partial_pk /* base2 */,
            element_bytes,
            ppk_cursor.h_vec + i * element_bytes /* element1 */,
            element_bytes,
            pk_proof_cursor.p_vec + i * element_bytes /* element2 */,
            element_bytes) != DLEQPROOF_SUCCESS) {
      return KDF_PK_PROOF_ERROR;
    }

    prev_partial_pk = pk_proof_cursor.p_vec + i * element_bytes;
  }

  return sodium_memcmp(prev_partial_pk, pk, element_bytes) == 0
      ? KDF_SUCCESS
      : KDF_PK_PROOF_ERROR;
}

static enum kdf_error derive_primary_public_key(
    kdf_t* kdf,
    unsigned char* ppk,
    size_t ppk_len,
    const unsigned char* primary_key,
    size_t primary_key_len) {
  if (ppk_len != kdf->primary_public_key_bytes ||
      primary_key_len != kdf->primary_key_bytes) {
    return KDF_BUFFER_LENGTH_ERROR;
  }
  memcpy(
      ppk,
      primary_key + kdf->primary_private_key_bytes,
      kdf->primary_public_key_bytes);
  return KDF_SUCCESS;
}

void kdf_naor_reingold_init(kdf_t* kdf, curve_t* curve) {
  kdf->curve = curve;
  kdf->primary_private_key_bytes =
      (1 + NAOR_REINGOLD_ATTRIBUTE_BITS) * curve->scalar_bytes;
  kdf->primary_public_key_bytes =
      (2 + NAOR_REINGOLD_ATTRIBUTE_BITS) * curve->element_bytes;
  kdf->primary_key_bytes =
      kdf->primary_private_key_bytes + kdf->primary_public_key_bytes;
  kdf->public_key_proof_bytes = NAOR_REINGOLD_ATTRIBUTE_BITS *
      (2 * curve->scalar_bytes + curve->element_bytes);
  kdf->generate_primary_key = generate_primary_key;
  kdf->derive_key_pair = derive_key_pair;
  kdf->verify_public_key = verify_public_key;
  kdf->derive_primary_public_key = derive_primary_public_key;
}
