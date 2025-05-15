/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "gen-cpp/SimpleAnonCredService.h"

extern "C" {
#include "src/crypto/curve/curve_ristretto.h"
#include "src/crypto/kdf/kdf_sdhi.h"
#include "src/crypto/voprf/voprf_mul_twohashdh.h"
}

namespace anon_cred {

using namespace thrift;

class SimpleAnonCredServiceHandler : virtual public SimpleAnonCredServiceIf {
 public:
  SimpleAnonCredServiceHandler();
  void getPrimaryPublicKey(GetPrimaryPublicKeyResponse& response);
  void getPublicKeyAndProof(
      GetPublicKeyResponse& response,
      const GetPublicKeyRequest& request);
  void signCredential(
      SignCredentialResponse& response,
      const SignCredentialRequest& request);
  void redeemCredential(const RedeemCredentialRequest& request);

 private:
  void deriveKeyPair(
      std::vector<unsigned char>& sk,
      std::vector<unsigned char>& pk,
      std::vector<unsigned char>& pkProof,
      const std::vector<std::string>& attributes);

  curve_t curve_;
  voprf_t voprf_;
  kdf_t kdf_;

  std::vector<unsigned char> primaryKey_;
};

} // namespace anon_cred
