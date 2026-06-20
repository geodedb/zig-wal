// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const crypto_backend = @import("crypto_backend");

test "wal crypto_backend seam round-trips AES-256-GCM" {
    const key = [_]u8{0x11} ** 32;
    const nonce = [_]u8{0x22} ** 12;
    const pt = "wal record payload";
    var ct: [pt.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try crypto_backend.Aead.seal(.aes_256_gcm, &key, &nonce, "aad", pt, &ct, &tag);
    var rt: [pt.len]u8 = undefined;
    try crypto_backend.Aead.open(.aes_256_gcm, &key, &nonce, "aad", &ct, &tag, &rt);
    try std.testing.expectEqualSlices(u8, pt, &rt);
    tag[0] ^= 0x01;
    try std.testing.expectError(error.AuthFailed, crypto_backend.Aead.open(.aes_256_gcm, &key, &nonce, "aad", &ct, &tag, &rt));
    crypto_backend.assertActive();
}
