/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "demo/SimpleAnonCredServiceHandler.h"
#include <iostream>
#include "demo/SimpleAnonCredUtils.h"

namespace anon_cred {

using namespace thrift;

SimpleAnonCredServiceHandler::SimpleAnonCredServiceHandler() {
  curve_ristretto_init(&curve_);
  voprf_mul_twohashdh_init(&voprf_, &curve_);
  kdf_sdhi_init(&kdf_, &curve_);
  auto primayKeyBytes = kdf_.primary_key_bytes;
  primaryKey_.resize(primayKeyBytes);
  kdf_.generate_primary_key(&kdf_, primaryKey_.data(), primayKeyBytes);
  std::cout << "Generated primary key: " << util::binToHex(primaryKey_)
            << std::endl;
}
void SimpleAnonCredServiceHandler::getPrimaryPublicKey(
    GetPrimaryPublicKeyResponse& response) {
  std::vector<unsigned char> primaryPublicKey(kdf_.primary_private_key_bytes);
  kdf_.derive_primary_public_key(
      &kdf_,
      primaryPublicKey.data(),
      primaryPublicKey.size(),
      primaryKey_.data(),
      primaryKey_.size());
  response.primay_public_key = util::binToHex(primaryPublicKey);
  std::cout << "Primary public key: " << util::binToHex(primaryPublicKey)
            << std::endl;
}

void SimpleAnonCredServiceHandler::getPublicKeyAndProof(
    GetPublicKeyResponse& response,
    const GetPublicKeyRequest& request) {
  std::vector<unsigned char> pk, sk, pkProof;
  deriveKeyPair(sk, pk, pkProof, request.attributes);
  response.public_key = util::binToHex(pk);
  response.public_key_proof = util::binToHex(pkProof);

  std::cout << "Public key: " << util::binToHex(pk) << std::endl;
  std::cout << "Public key proof: " << util::binToHex(pkProof) << std::endl;
}

void SimpleAnonCredServiceHandler::signCredential(
    SignCredentialResponse& response,
    const SignCredentialRequest& request) {
  auto elementBytes = curve_.element_bytes;
  auto scalarBytes = curve_.scalar_bytes;
  std::vector<unsigned char> pk, sk, pkProof;
  deriveKeyPair(sk, pk, pkProof, request.attributes);
  auto blindedElement =
      util::hexToBin(request.blinded_token, request.blinded_token.size() / 2);
  std::vector<unsigned char> blindedSignature(elementBytes);
  std::vector<unsigned char> proofC(scalarBytes);
  std::vector<unsigned char> proofS(scalarBytes);
  auto evaluateErrorcode = voprf_.evaluate(
      &voprf_,
      blindedSignature.data(),
      blindedSignature.size(),
      proofC.data(),
      proofC.size(),
      proofS.data(),
      proofS.size(),
      sk.data(),
      sk.size(),
      blindedElement.data(),
      blindedElement.size(),
      1);
  if (evaluateErrorcode != VOPRF_SUCCESS) {
    VoprfErrorException exception;
    exception.errorcode = evaluateErrorcode;
    exception.message = "signCredential throws voprf_error, see voprf.h";
    throw exception;
  }

  response.evaluated_token = util::binToHex(blindedSignature);
  response.proof_c = util::binToHex(proofC);
  response.proof_s = util::binToHex(proofS);

  std::cout << "Blinded token: " << request.blinded_token << std::endl;
  std::cout << "Evaluated token: " << response.evaluated_token << std::endl;
  std::cout << "Proof.c: " << response.proof_c << std::endl;
  std::cout << "Proof.s: " << response.proof_s << std::endl;
}

// TODO: Add check for token expiration and reuse limit
void SimpleAnonCredServiceHandler::redeemCredential(
    const RedeemCredentialRequest& request) {
  auto elementBytes = curve_.element_bytes;
  auto scalarBytes = curve_.scalar_bytes;
  std::vector<unsigned char> pk, sk, pkProof;
  deriveKeyPair(sk, pk, pkProof, request.attributes);
  auto finalEvaluationBytes = voprf_.final_evaluation_bytes;
  std::vector<unsigned char> finalEvaluation(finalEvaluationBytes);
  auto serverFinalizeErrorcode = voprf_.server_finalize(
      &voprf_,
      finalEvaluation.data(),
      finalEvaluation.size(),
      (const unsigned char*)request.token.data(),
      request.token.size(),
      sk.data(),
      sk.size());
  if (serverFinalizeErrorcode != VOPRF_SUCCESS) {
    VoprfErrorException exception;
    exception.errorcode = serverFinalizeErrorcode;
    exception.message = "redeemCredential throws voprf_error, see voprf.h";
    throw exception;
  }
  std::cout << "Server secret: " << util::binToHex(finalEvaluation)
            << std::endl;
  std::cout << "Client secret: " << request.shared_secret << std::endl;
  auto clientEvaluation =
      util::hexToBin(request.shared_secret, finalEvaluationBytes);
  if (sodium_memcmp(
          clientEvaluation.data(),
          finalEvaluation.data(),
          finalEvaluationBytes) != 0) {
    CredentialMismatchException exception;
    exception.message =
        "Secrets mismatch, client secret: " + request.shared_secret;
    throw exception;
  }
  std::cout << "Redeem credential success!" << std::endl;
}

void SimpleAnonCredServiceHandler::deriveKeyPair(
    std::vector<unsigned char>& sk,
    std::vector<unsigned char>& pk,
    std::vector<unsigned char>& pkProof,
    const std::vector<std::string>& attributes) {
  auto elementBytes = curve_.element_bytes;
  auto scalarBytes = curve_.scalar_bytes;
  auto pkProofBytes = kdf_.public_key_proof_bytes;
  sk.resize(scalarBytes);
  pk.resize(elementBytes);
  pkProof.resize(pkProofBytes);
  auto attributeArrSize = attributes.size();
  std::vector<const unsigned char*> attributeArr;
  std::vector<size_t> attributeLenArr;
  for (const std::string& s : attributes) {
    attributeLenArr.push_back(s.size());
    attributeArr.push_back((const unsigned char*)s.data());
  }
  kdf_.derive_key_pair(
      &kdf_,
      sk.data(),
      sk.size(),
      pk.data(),
      pk.size(),
      pkProof.data(),
      pkProof.size(),
      primaryKey_.data(),
      primaryKey_.size(),
      attributeArrSize,
      attributeArr.data(),
      attributeLenArr.data(),
      1);
}

} // namespace anon_cred
