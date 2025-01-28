/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "src/crypto/curve/curve.h"

/**
 * Implementation for curve ed25519.
 * Example:
 *   curve_t c;
 *   curve_ed25519_init(&c);
 *   unsigned char r[c.scalar_bytes];
 *   c.scalar_random(r, c.scalar_bytes);
 */

void curve_ed25519_init(curve_t* /* curve */);
