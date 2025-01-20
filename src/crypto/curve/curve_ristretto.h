/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "src/crypto/curve/curve.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Implementation for curve ristretto.
 * Example:
 *   curve_t c;
 *   curve_ristretto_init(&c);
 *   unsigned char r[c.scalar_bytes];
 *   c.scalar_random(r, c.scalar_bytes);
 */

void curve_ristretto_init(curve_t* /* curve */);

#ifdef __cplusplus
}
#endif
