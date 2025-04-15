/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sodium.h>

#include "src/crypto/kdf/kdf.h"

/**
 * Implementation for KDF naor reingold.
 *
 * This is a KDF inspired by the Naor-Reingold PRF. The size of primary keys are
 * relatively large (about 256 * kdf_sdhi).
 *
 * See https://research.fb.com/dit for details.
 */

void kdf_naor_reingold_init(kdf_t* /* kdf */, curve_t* /* curve */);
