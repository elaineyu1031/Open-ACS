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
#include "src/crypto/curve/curve.h"
#include "src/crypto/curve/curve_ed25519.h"
#include "src/crypto/curve/curve_ristretto.h"
#include "src/crypto/dleqproof/dleqproof.h"
}

namespace {

enum class CryptoCurve {
  CURVE_RISTRETTO,
  CURVE_ED25519,
};

struct DleqproofTest : public testing::TestWithParam<CryptoCurve> {
  void SetUp() override {
    switch (GetParam()) {
      case CryptoCurve::CURVE_ED25519:
        curve_ed25519_init(&curve_);
        break;
      case CryptoCurve::CURVE_RISTRETTO:
        curve_ristretto_init(&curve_);
        break;
    }
    dleqproof_init(&protocol_, &curve_);
  }

  void TearDown() override {}

  curve_t curve_;
  dleqproof_protocol_t protocol_;
};

TEST_P(DleqproofTest, ProveAndVerifyTest) {
  unsigned char x1[curve_.scalar_bytes];
  unsigned char x2[curve_.scalar_bytes];
  unsigned char base1[curve_.element_bytes];
  unsigned char base2[curve_.element_bytes];
  unsigned char element1[curve_.element_bytes];
  unsigned char element2[curve_.element_bytes];
  unsigned char proof_c[curve_.scalar_bytes];
  unsigned char proof_s[curve_.scalar_bytes];

  curve_.scalar_random(x1, curve_.scalar_bytes);
  curve_.scalar_random(x2, curve_.scalar_bytes);
  curve_.get_generator(base1, curve_.element_bytes);

  // initialize base2 and make it on curve
  unsigned char* token = (unsigned char*)"test";
  const size_t token_len = 4;
  curve_.hash_to_curve(
      base2, (const unsigned char*[]){token}, (const size_t[]){token_len}, 1);

  curve_.group_exp(
      element1,
      curve_.element_bytes,
      x1,
      curve_.scalar_bytes,
      base1,
      curve_.element_bytes);
  curve_.group_exp(
      element2,
      curve_.element_bytes,
      x1,
      curve_.scalar_bytes,
      base2,
      curve_.element_bytes);

  // Prove and verify
  EXPECT_EQ(
      protocol_.prove(
          &protocol_,
          proof_c,
          curve_.scalar_bytes,
          proof_s,
          curve_.scalar_bytes,
          base1,
          curve_.element_bytes,
          base2,
          curve_.element_bytes,
          element1,
          curve_.element_bytes,
          element2,
          curve_.element_bytes,
          x1,
          curve_.scalar_bytes),
      DLEQPROOF_SUCCESS);
  EXPECT_EQ(
      protocol_.verify(
          &protocol_,
          proof_c,
          curve_.scalar_bytes,
          proof_s,
          curve_.scalar_bytes,
          base1,
          curve_.element_bytes,
          base2,
          curve_.element_bytes,
          element1,
          curve_.element_bytes,
          element2,
          curve_.element_bytes),
      DLEQPROOF_SUCCESS);

  // Fail to verify by providing different discrete log
  EXPECT_EQ(
      protocol_.prove(
          &protocol_,
          proof_c,
          curve_.scalar_bytes,
          proof_s,
          curve_.scalar_bytes,
          base1,
          curve_.element_bytes,
          base2,
          curve_.element_bytes,
          element1,
          curve_.element_bytes,
          element2,
          curve_.element_bytes,
          x2,
          curve_.scalar_bytes),
      DLEQPROOF_SUCCESS);
  EXPECT_EQ(
      protocol_.verify(
          &protocol_,
          proof_c,
          curve_.scalar_bytes,
          proof_s,
          curve_.scalar_bytes,
          base1,
          curve_.element_bytes,
          base2,
          curve_.element_bytes,
          element1,
          curve_.element_bytes,
          element2,
          curve_.element_bytes),
      DLEQPROOF_VERIFY_FAIL);

  // Fail to verify by providing wrong base
  EXPECT_EQ(
      protocol_.prove(
          &protocol_,
          proof_c,
          curve_.scalar_bytes,
          proof_s,
          curve_.scalar_bytes,
          base2,
          curve_.element_bytes,
          base2,
          curve_.element_bytes,
          element1,
          curve_.element_bytes,
          element2,
          curve_.element_bytes,
          x1,
          curve_.scalar_bytes),
      DLEQPROOF_SUCCESS);
  EXPECT_EQ(
      protocol_.verify(
          &protocol_,
          proof_c,
          curve_.scalar_bytes,
          proof_s,
          curve_.scalar_bytes,
          base1,
          curve_.element_bytes,
          base2,
          curve_.element_bytes,
          element1,
          curve_.element_bytes,
          element2,
          curve_.element_bytes),
      DLEQPROOF_VERIFY_FAIL);
}

TEST_P(DleqproofTest, NotOnCurveTest) {
  unsigned char x[curve_.scalar_bytes];
  unsigned char base1[curve_.element_bytes];
  unsigned char base2[curve_.element_bytes];
  unsigned char proof_c[curve_.scalar_bytes];
  unsigned char proof_s[curve_.scalar_bytes];
  unsigned char element1[curve_.element_bytes];
  unsigned char element2[curve_.element_bytes];

  curve_.scalar_random(x, curve_.scalar_bytes);
  curve_.get_generator(base1, curve_.element_bytes);

  // initialize base2 and make it not on curve
  char h[] = "cd10942ca1885798e1987b43b068f9b8f344576b44f570a5debf734949210960";
  sodium_hex2bin(base2, curve_.element_bytes, h, strlen(h), NULL, NULL, NULL);

  curve_.group_exp(
      element1,
      curve_.element_bytes,
      x,
      curve_.scalar_bytes,
      base1,
      curve_.element_bytes);
  curve_.group_exp(
      element2,
      curve_.element_bytes,
      x,
      curve_.scalar_bytes,
      base2,
      curve_.element_bytes);

  EXPECT_EQ(
      protocol_.prove(
          &protocol_,
          proof_c,
          curve_.scalar_bytes,
          proof_s,
          curve_.scalar_bytes,
          base1,
          curve_.element_bytes,
          base2,
          curve_.element_bytes,
          element1,
          curve_.element_bytes,
          element2,
          curve_.element_bytes,
          x,
          curve_.scalar_bytes),
      DLEQPROOF_CURVE_OPERATION_ERROR);
}

INSTANTIATE_TEST_SUITE_P(
    VOPRFLib,
    DleqproofTest,
    testing::Values(CryptoCurve::CURVE_ED25519, CryptoCurve::CURVE_RISTRETTO));

} // namespace
