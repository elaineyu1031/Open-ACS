/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sodium.h>
extern "C" {
#include "src/crypto/curve/curve_ed25519.h"
#include "src/crypto/curve/curve_ristretto.h"
#include "src/crypto/kdf/kdf_default.h"
#include "src/crypto/kdf/kdf_naor_reingold.h"
#include "src/crypto/kdf/kdf_sdhi.h"
#include "src/crypto/voprf/voprf_exp_twohashdh.h"
#include "src/crypto/voprf/voprf_mul_twohashdh.h"
}

namespace {

enum class CryptoCurve {
  CURVE_RISTRETTO,
  CURVE_ED25519,
};

enum class Kdf {
  KDF_DEFAULT,
  KDF_NAOR_REINGOLD,
  KDF_SDHI,
};

enum class Blinding {
  MULTIPLICATIVE,
  EXPONENTIAL,
};

struct KdfTest
    : public testing::TestWithParam<std::tuple<CryptoCurve, Kdf, Blinding>> {
  void SetUp() override {
    auto testParam = GetParam();
    switch (std::get<0>(testParam)) {
      case CryptoCurve::CURVE_ED25519:
        curve_ed25519_init(&curve_);
        break;
      case CryptoCurve::CURVE_RISTRETTO:
        curve_ristretto_init(&curve_);
        break;
    }
    switch (std::get<1>(testParam)) {
      case Kdf::KDF_DEFAULT:
        kdf_default_init(&kdf_, &curve_);
        break;
      case Kdf::KDF_SDHI:
        kdf_sdhi_init(&kdf_, &curve_);
        break;
      case Kdf::KDF_NAOR_REINGOLD:
        // kdf_sdhi_init(&kdf_, &curve_);
        kdf_naor_reingold_init(&kdf_, &curve_);
        break;
    }
    switch (std::get<2>(testParam)) {
      case Blinding::EXPONENTIAL:
        voprf_exp_twohashdh_init(&voprf_, &curve_);
        break;
      case Blinding::MULTIPLICATIVE:
        voprf_mul_twohashdh_init(&voprf_, &curve_);
        break;
    }
  }

  void TearDown() override {}

  curve_t curve_;
  kdf_t kdf_;
  voprf_t voprf_;
};

TEST_P(KdfTest, KeyPairTest) {
  const size_t primary_key_len = kdf_.primary_key_bytes;
  unsigned char primary_key[primary_key_len];
  EXPECT_EQ(
      kdf_.generate_primary_key(&kdf_, primary_key, primary_key_len),
      KDF_SUCCESS);

  const unsigned char* attribute_arr[2] = {
      (const unsigned char*)"some_random_string",
      (const unsigned char*)"123456"};
  const size_t attribute_len_arr[2] = {18, 6};

  const size_t sk_len = curve_.scalar_bytes;
  const size_t pk_len = curve_.element_bytes;
  unsigned char sk[sk_len];
  unsigned char pk[pk_len];
  EXPECT_EQ(
      kdf_.derive_key_pair(
          &kdf_,
          sk,
          sk_len,
          pk,
          pk_len,
          NULL,
          0,
          primary_key,
          primary_key_len,
          2,
          attribute_arr,
          attribute_len_arr,
          0),
      KDF_SUCCESS);

  // Check g^sk = pk for derived key pair
  unsigned char g_sk[pk_len];
  curve_.group_exp_generator(
      g_sk, curve_.element_bytes, sk, curve_.scalar_bytes);
  EXPECT_EQ(sodium_memcmp(g_sk, pk, curve_.element_bytes), 0);
}

TEST_P(KdfTest, ProofTest) {
  size_t primary_key_len = kdf_.primary_key_bytes;
  unsigned char primary_key[primary_key_len];
  EXPECT_EQ(
      kdf_.generate_primary_key(&kdf_, primary_key, primary_key_len),
      KDF_SUCCESS);

  const unsigned char* attribute_arr[2] = {
      (const unsigned char*)"some_random_string",
      (const unsigned char*)"123456"};
  const unsigned char* another_attribute_arr[2] = {
      (const unsigned char*)"some_random_string",
      (const unsigned char*)"abcdef"};
  const size_t attribute_len_arr[2] = {18, 6};

  size_t sk_len = curve_.scalar_bytes;
  size_t pk_len = curve_.element_bytes;
  size_t pk_proof_len = kdf_.public_key_proof_bytes;
  unsigned char sk[sk_len];
  unsigned char pk[pk_len];
  unsigned char pk_proof[pk_proof_len];
  EXPECT_EQ(
      kdf_.derive_key_pair(
          &kdf_,
          sk,
          sk_len,
          pk,
          pk_len,
          pk_proof,
          pk_proof_len,
          primary_key,
          primary_key_len,
          2,
          attribute_arr,
          attribute_len_arr,
          1),
      KDF_SUCCESS);

  unsigned char ppk[kdf_.primary_public_key_bytes];
  kdf_.derive_primary_public_key(
      &kdf_, ppk, kdf_.primary_public_key_bytes, primary_key, primary_key_len);
  EXPECT_EQ(
      kdf_.verify_public_key(
          &kdf_,
          pk,
          pk_len,
          pk_proof,
          pk_proof_len,
          ppk,
          kdf_.primary_public_key_bytes,
          2,
          attribute_arr,
          attribute_len_arr),
      KDF_SUCCESS);

  if (pk_proof_len > 0) {
    // pass another attribute array, verification should fail
    EXPECT_EQ(
        kdf_.verify_public_key(
            &kdf_,
            pk,
            pk_len,
            pk_proof,
            pk_proof_len,
            ppk,
            kdf_.primary_public_key_bytes,
            2,
            another_attribute_arr,
            attribute_len_arr),
        KDF_PK_PROOF_ERROR);

    // corrupt proof byte to make proof verification fail
    pk_proof[0] += 1;
    EXPECT_EQ(
        kdf_.verify_public_key(
            &kdf_,
            pk,
            pk_len,
            pk_proof,
            pk_proof_len,
            ppk,
            kdf_.primary_public_key_bytes,
            2,
            attribute_arr,
            attribute_len_arr),
        KDF_PK_PROOF_ERROR);
  }
}

TEST_P(KdfTest, VoprfWorkflowTest) {
  const size_t primary_key_len = kdf_.primary_key_bytes;
  unsigned char primary_key[primary_key_len];
  EXPECT_EQ(
      kdf_.generate_primary_key(&kdf_, primary_key, primary_key_len),
      KDF_SUCCESS);

  const unsigned char* attribute_arr[2] = {
      (const unsigned char*)"some_random_string",
      (const unsigned char*)"123456"};
  const size_t attribute_len_arr[2] = {18, 6};

  const size_t sk_len = curve_.scalar_bytes;
  const size_t pk_len = curve_.element_bytes;
  unsigned char sk[sk_len];
  unsigned char pk[pk_len];
  EXPECT_EQ(
      kdf_.derive_key_pair(
          &kdf_,
          sk,
          sk_len,
          pk,
          pk_len,
          NULL,
          0,
          primary_key,
          primary_key_len,
          2,
          attribute_arr,
          attribute_len_arr,
          0),
      KDF_SUCCESS);

  unsigned char* token = (unsigned char*)"test";
  const size_t token_len = 4;

  // blind
  const size_t blinded_element_len = curve_.element_bytes;
  const size_t blinding_factor_len = curve_.scalar_bytes;
  unsigned char blinded_element[blinded_element_len];
  unsigned char blinding_factor[blinding_factor_len];
  EXPECT_EQ(
      voprf_.blind(
          &voprf_,
          blinded_element,
          blinded_element_len,
          blinding_factor,
          blinding_factor_len,
          token,
          token_len),
      VOPRF_SUCCESS);

  // evaluate
  const size_t evaluated_element_len = curve_.element_bytes;
  unsigned char evaluated_element[evaluated_element_len];
  const size_t proof_c_len = curve_.scalar_bytes;
  unsigned char proof_c[proof_c_len];
  const size_t proof_s_len = curve_.scalar_bytes;
  unsigned char proof_s[proof_s_len];
  EXPECT_EQ(
      voprf_.evaluate(
          &voprf_,
          evaluated_element,
          evaluated_element_len,
          proof_c,
          proof_c_len,
          proof_s,
          proof_s_len,
          sk,
          sk_len,
          blinded_element,
          blinded_element_len,
          1 /* flag_proof_generate */),
      VOPRF_SUCCESS);

  // unblind
  const size_t unblinded_element_len = curve_.element_bytes;
  unsigned char unblinded_element[unblinded_element_len];
  EXPECT_EQ(
      voprf_.verifiable_unblind(
          &voprf_,
          unblinded_element,
          unblinded_element_len,
          proof_c,
          proof_c_len,
          proof_s,
          proof_s_len,
          blinding_factor,
          blinding_factor_len,
          evaluated_element,
          evaluated_element_len,
          blinded_element,
          blinded_element_len,
          pk,
          pk_len,
          1 /* flag_proof_verify */),
      VOPRF_SUCCESS);

  // client finalize
  const size_t client_secret_len = voprf_.final_evaluation_bytes;
  unsigned char client_secret[client_secret_len];
  EXPECT_EQ(
      voprf_.client_finalize(
          &voprf_,
          client_secret,
          client_secret_len,
          token,
          token_len,
          unblinded_element,
          unblinded_element_len),
      VOPRF_SUCCESS);

  // server finalize
  const size_t server_secret_len = voprf_.final_evaluation_bytes;
  unsigned char server_secret[server_secret_len];
  EXPECT_EQ(
      voprf_.server_finalize(
          &voprf_,
          server_secret,
          server_secret_len,
          token,
          token_len,
          sk,
          sk_len),
      VOPRF_SUCCESS);

  EXPECT_EQ(
      sodium_memcmp(
          client_secret, server_secret, voprf_.final_evaluation_bytes),
      0);
}

INSTANTIATE_TEST_SUITE_P(
    VariableCurveKDFBlinding,
    KdfTest,
    testing::Combine(
        testing::Values(
            CryptoCurve::CURVE_ED25519,
            CryptoCurve::CURVE_RISTRETTO),
        testing::Values(
            Kdf::KDF_DEFAULT,
            Kdf::KDF_SDHI,
            Kdf::KDF_NAOR_REINGOLD),
        testing::Values(Blinding::MULTIPLICATIVE, Blinding::EXPONENTIAL)));

} // namespace
