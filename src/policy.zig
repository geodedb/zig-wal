// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! CANONICAL FILE — copied verbatim into each consumer's src/ for the
//! NON-fips path (alongside std_shim.zig). Pure comptime: no @cImport,
//! no OpenSSL, no `c.*`. std_shim.zig imports THIS file via
//! `@import("policy.zig")`. Keep byte-identical across fips + std_shim.
//!
//! Comptime FIPS-approved algorithm allow-list. Consumer libs gate
//! against `policy.isApproved` and the zlint rule references this table.
//! Every string is the exact OpenSSL 3.x fetch name (confirmed via
//! `openssl list` against 3.6.2).
const std = @import("std");

pub const Hash = enum { sha256, sha384, sha512, sha3_256, sha3_384, sha3_512 };
pub const Mac = enum { hmac_sha256, hmac_sha384, hmac_sha512 };
pub const Kdf = enum { hkdf, pbkdf2 };
pub const Aead = enum { aes_128_gcm, aes_256_gcm };
pub const SigAlg = enum {
    ecdsa_p256,
    ecdsa_p384,
    ecdsa_p521,
    rsa_pss,
    rsa_pkcs1,
    ed25519,
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,
    slh_dsa_sha2_128s,
    slh_dsa_sha2_128f,
    slh_dsa_sha2_192s,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_256s,
    slh_dsa_sha2_256f,
    slh_dsa_shake_128s,
    slh_dsa_shake_128f,
    slh_dsa_shake_192s,
    slh_dsa_shake_192f,
    slh_dsa_shake_256s,
    slh_dsa_shake_256f,
};
pub const KemAlg = enum {
    ml_kem_512,
    ml_kem_768,
    ml_kem_1024,
    x25519_ml_kem_768,
    x448_ml_kem_1024,
    secp256r1_ml_kem_768,
    secp384r1_ml_kem_1024,
};

pub fn hashName(a: Hash) [:0]const u8 {
    return switch (a) {
        .sha256 => "SHA2-256",
        .sha384 => "SHA2-384",
        .sha512 => "SHA2-512",
        .sha3_256 => "SHA3-256",
        .sha3_384 => "SHA3-384",
        .sha3_512 => "SHA3-512",
    };
}
pub fn aeadName(a: Aead) [:0]const u8 {
    return switch (a) {
        .aes_128_gcm => "AES-128-GCM",
        .aes_256_gcm => "AES-256-GCM",
    };
}
pub fn kdfName(a: Kdf) [:0]const u8 {
    return switch (a) {
        .hkdf => "HKDF",
        .pbkdf2 => "PBKDF2",
    };
}
pub fn sigName(a: SigAlg) [:0]const u8 {
    return switch (a) {
        .ecdsa_p256, .ecdsa_p384, .ecdsa_p521 => "ECDSA",
        .rsa_pss, .rsa_pkcs1 => "RSA",
        .ed25519 => "ED25519",
        .ml_dsa_44 => "ML-DSA-44",
        .ml_dsa_65 => "ML-DSA-65",
        .ml_dsa_87 => "ML-DSA-87",
        .slh_dsa_sha2_128s => "SLH-DSA-SHA2-128s",
        .slh_dsa_sha2_128f => "SLH-DSA-SHA2-128f",
        .slh_dsa_sha2_192s => "SLH-DSA-SHA2-192s",
        .slh_dsa_sha2_192f => "SLH-DSA-SHA2-192f",
        .slh_dsa_sha2_256s => "SLH-DSA-SHA2-256s",
        .slh_dsa_sha2_256f => "SLH-DSA-SHA2-256f",
        .slh_dsa_shake_128s => "SLH-DSA-SHAKE-128s",
        .slh_dsa_shake_128f => "SLH-DSA-SHAKE-128f",
        .slh_dsa_shake_192s => "SLH-DSA-SHAKE-192s",
        .slh_dsa_shake_192f => "SLH-DSA-SHAKE-192f",
        .slh_dsa_shake_256s => "SLH-DSA-SHAKE-256s",
        .slh_dsa_shake_256f => "SLH-DSA-SHAKE-256f",
    };
}
pub fn kemName(a: KemAlg) [:0]const u8 {
    return switch (a) {
        .ml_kem_512 => "ML-KEM-512",
        .ml_kem_768 => "ML-KEM-768",
        .ml_kem_1024 => "ML-KEM-1024",
        .x25519_ml_kem_768 => "X25519MLKEM768",
        .x448_ml_kem_1024 => "X448MLKEM1024",
        .secp256r1_ml_kem_768 => "SecP256r1MLKEM768",
        .secp384r1_ml_kem_1024 => "SecP384r1MLKEM1024",
    };
}

const approved_names = [_][]const u8{
    "SHA2-256",           "SHA2-384",           "SHA2-512",           "SHA3-256",           "SHA3-384",           "SHA3-512",
    "HMAC",               "HKDF",               "PBKDF2",             "AES-128-GCM",        "AES-256-GCM",        "AES-256-CBC",
    "ECDSA",              "RSA",                "ED25519",            "ML-DSA-44",          "ML-DSA-65",          "ML-DSA-87",
    "ML-KEM-512",         "ML-KEM-768",         "ML-KEM-1024",        "X25519MLKEM768",     "X448MLKEM1024",      "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024", "SLH-DSA-SHA2-128s",  "SLH-DSA-SHA2-128f",  "SLH-DSA-SHA2-192s",  "SLH-DSA-SHA2-192f",  "SLH-DSA-SHA2-256s",
    "SLH-DSA-SHA2-256f",  "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s",
    "SLH-DSA-SHAKE-256f",
};

pub fn isApproved(comptime name: []const u8) bool {
    inline for (approved_names) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

test "approved table accepts AES-256-GCM, rejects ChaCha20-Poly1305" {
    try std.testing.expect(isApproved("AES-256-GCM"));
    try std.testing.expect(isApproved("ML-KEM-768"));
    try std.testing.expect(!isApproved("ChaCha20-Poly1305"));
    try std.testing.expect(!isApproved("Argon2id"));
    try std.testing.expect(!isApproved("BLAKE3"));
}
test "names match openssl fetch strings" {
    try std.testing.expectEqualStrings("AES-256-GCM", aeadName(.aes_256_gcm));
    try std.testing.expectEqualStrings("X25519MLKEM768", kemName(.x25519_ml_kem_768));
    try std.testing.expectEqualStrings("SLH-DSA-SHAKE-256f", sigName(.slh_dsa_shake_256f));
}
