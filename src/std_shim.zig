// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! CANONICAL FILE — copied verbatim into each consumer's src/ for the
//! NON-fips path (alongside policy.zig). Imports ONLY `std` + the local
//! sibling `policy.zig` (`@import("policy.zig")`), so a non-fips build
//! needs NO `fips` dependency, NO OpenSSL, NO @cImport.
//!
//! std.crypto-backed backend mirroring the fips backend's public surface
//! EXACTLY (Hash/Mac/Kdf incl. hkdfExpand, Aead, Sig, Kem incl. the
//! pinned Kem.EncapResult, Csprng, assertActive). RSA and all PQC
//! (ML-DSA/SLH-DSA, ML-KEM + hybrids) are fips-only and return
//! error.Unsupported here.
const std = @import("std");
pub const policy = @import("policy.zig");

fn randomBytes(out: []u8) void {
    // Linux getrandom syscall; the non-fips shim's CSPRNG.
    var off: usize = 0;
    while (off < out.len) {
        const rc = std.os.linux.getrandom(out.ptr + off, out.len - off, 0);
        const n: isize = @bitCast(rc);
        if (n < 0) {
            // EINTR/EAGAIN: retry; anything else: fall back to a re-seed.
            continue;
        }
        off += @intCast(n);
    }
}

pub const Hash = struct {
    pub const Error = error{ Unsupported, OpensslFailure };
    pub fn digest(alg: policy.Hash, msg: []const u8, out: []u8) Error!usize {
        switch (alg) {
            .sha256 => return one(std.crypto.hash.sha2.Sha256, msg, out),
            .sha384 => return one(std.crypto.hash.sha2.Sha384, msg, out),
            .sha512 => return one(std.crypto.hash.sha2.Sha512, msg, out),
            .sha3_256 => return one(std.crypto.hash.sha3.Sha3_256, msg, out),
            .sha3_384 => return one(std.crypto.hash.sha3.Sha3_384, msg, out),
            .sha3_512 => return one(std.crypto.hash.sha3.Sha3_512, msg, out),
        }
    }
    fn one(comptime H: type, msg: []const u8, out: []u8) Error!usize {
        var d: [H.digest_length]u8 = undefined;
        H.hash(msg, &d, .{});
        if (out.len < d.len) return error.OpensslFailure;
        @memcpy(out[0..d.len], &d);
        return d.len;
    }
};

pub const Mac = struct {
    pub const Error = error{OpensslFailure};
    pub fn hmac(alg: policy.Hash, key: []const u8, msg: []const u8, out: []u8) Error!usize {
        switch (alg) {
            .sha256 => return one(std.crypto.auth.hmac.sha2.HmacSha256, key, msg, out),
            .sha384 => return one(std.crypto.auth.hmac.sha2.HmacSha384, key, msg, out),
            .sha512 => return one(std.crypto.auth.hmac.sha2.HmacSha512, key, msg, out),
            // HMAC over SHA-3 is not a std builtin; build it generically.
            .sha3_256 => return one(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_256), key, msg, out),
            .sha3_384 => return one(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_384), key, msg, out),
            .sha3_512 => return one(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_512), key, msg, out),
        }
    }
    fn one(comptime M: type, key: []const u8, msg: []const u8, out: []u8) Error!usize {
        var t: [M.mac_length]u8 = undefined;
        M.create(&t, msg, key);
        if (out.len < t.len) return error.OpensslFailure;
        @memcpy(out[0..t.len], &t);
        return t.len;
    }
};

pub const Kdf = struct {
    pub const Error = error{OpensslFailure};

    pub fn hkdf(hash: policy.Hash, ikm: []const u8, salt: []const u8, info: []const u8, out: []u8) Error!void {
        switch (hash) {
            .sha256 => return hk(std.crypto.auth.hmac.sha2.HmacSha256, ikm, salt, info, out),
            .sha384 => return hk(std.crypto.auth.hmac.sha2.HmacSha384, ikm, salt, info, out),
            .sha512 => return hk(std.crypto.auth.hmac.sha2.HmacSha512, ikm, salt, info, out),
            .sha3_256 => return hk(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_256), ikm, salt, info, out),
            .sha3_384 => return hk(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_384), ikm, salt, info, out),
            .sha3_512 => return hk(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_512), ikm, salt, info, out),
        }
    }
    fn hk(comptime Hmac: type, ikm: []const u8, salt: []const u8, info: []const u8, out: []u8) Error!void {
        const H = std.crypto.kdf.hkdf.Hkdf(Hmac);
        const prk = H.extract(salt, ikm);
        if (out.len > H.prk_length * 255) return error.OpensslFailure;
        H.expand(out, info, prk);
    }

    pub fn hkdfExpand(hash: policy.Hash, prk: []const u8, info: []const u8, out: []u8) Error!void {
        switch (hash) {
            .sha256 => return hke(std.crypto.auth.hmac.sha2.HmacSha256, prk, info, out),
            .sha384 => return hke(std.crypto.auth.hmac.sha2.HmacSha384, prk, info, out),
            .sha512 => return hke(std.crypto.auth.hmac.sha2.HmacSha512, prk, info, out),
            .sha3_256 => return hke(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_256), prk, info, out),
            .sha3_384 => return hke(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_384), prk, info, out),
            .sha3_512 => return hke(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_512), prk, info, out),
        }
    }
    fn hke(comptime Hmac: type, prk: []const u8, info: []const u8, out: []u8) Error!void {
        const H = std.crypto.kdf.hkdf.Hkdf(Hmac);
        if (prk.len != H.prk_length) return error.OpensslFailure;
        if (out.len > H.prk_length * 255) return error.OpensslFailure;
        var prk_arr: [H.prk_length]u8 = undefined;
        @memcpy(&prk_arr, prk[0..H.prk_length]);
        H.expand(out, info, prk_arr);
    }

    pub fn pbkdf2(hash: policy.Hash, password: []const u8, salt: []const u8, iters: u32, out: []u8) Error!void {
        switch (hash) {
            .sha256 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.sha2.HmacSha256) catch return error.OpensslFailure,
            .sha384 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.sha2.HmacSha384) catch return error.OpensslFailure,
            .sha512 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.sha2.HmacSha512) catch return error.OpensslFailure,
            .sha3_256 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_256)) catch return error.OpensslFailure,
            .sha3_384 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_384)) catch return error.OpensslFailure,
            .sha3_512 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_512)) catch return error.OpensslFailure,
        }
    }
};

pub const Aead = struct {
    pub const Error = error{ Unsupported, AuthFailed, OpensslFailure };
    pub fn seal(alg: policy.Aead, key: []const u8, nonce: []const u8, ad: []const u8, plaintext: []const u8, ciphertext: []u8, tag: []u8) Error!void {
        switch (alg) {
            .aes_128_gcm => return sl(std.crypto.aead.aes_gcm.Aes128Gcm, key, nonce, ad, plaintext, ciphertext, tag),
            .aes_256_gcm => return sl(std.crypto.aead.aes_gcm.Aes256Gcm, key, nonce, ad, plaintext, ciphertext, tag),
        }
    }
    pub fn open(alg: policy.Aead, key: []const u8, nonce: []const u8, ad: []const u8, ciphertext: []const u8, tag: []const u8, plaintext: []u8) Error!void {
        switch (alg) {
            .aes_128_gcm => return op(std.crypto.aead.aes_gcm.Aes128Gcm, key, nonce, ad, ciphertext, tag, plaintext),
            .aes_256_gcm => return op(std.crypto.aead.aes_gcm.Aes256Gcm, key, nonce, ad, ciphertext, tag, plaintext),
        }
    }
    fn sl(comptime A: type, key: []const u8, nonce: []const u8, ad: []const u8, pt: []const u8, ct: []u8, tag: []u8) Error!void {
        if (key.len != A.key_length or nonce.len != A.nonce_length or tag.len != A.tag_length or ct.len < pt.len) return error.OpensslFailure;
        var t: [A.tag_length]u8 = undefined;
        A.encrypt(ct[0..pt.len], &t, pt, ad, nonce[0..A.nonce_length].*, key[0..A.key_length].*);
        @memcpy(tag[0..A.tag_length], &t);
    }
    fn op(comptime A: type, key: []const u8, nonce: []const u8, ad: []const u8, ct: []const u8, tag: []const u8, pt: []u8) Error!void {
        if (key.len != A.key_length or nonce.len != A.nonce_length or tag.len != A.tag_length or pt.len < ct.len) return error.OpensslFailure;
        A.decrypt(pt[0..ct.len], ct, tag[0..A.tag_length].*, ad, nonce[0..A.nonce_length].*, key[0..A.key_length].*) catch return error.AuthFailed;
    }
};

pub const Sig = struct {
    pub const Error = error{ Unsupported, VerifyFailed, OpensslFailure };

    const Ed25519 = std.crypto.sign.Ed25519;
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
    // NB: std.crypto has no P-521 curve, so ECDSA P-521 is fips-only in
    // the non-fips shim (returns error.Unsupported), like RSA/PQC.

    const Inner = union(enum) {
        ed25519: Ed25519.KeyPair,
        p256: P256.KeyPair,
        p384: P384.KeyPair,
        ed25519_pub: Ed25519.PublicKey,
        p256_pub: P256.PublicKey,
        p384_pub: P384.PublicKey,
    };

    pub const KeyPair = struct {
        inner: Inner,

        pub fn deinit(self: *KeyPair) void {
            _ = self; // std keys carry no heap state
        }

        pub fn publicBytes(self: *KeyPair, out: []u8) Error!usize {
            return switch (self.inner) {
                .ed25519 => |kp| copyOut(out, &kp.public_key.toBytes()),
                .ed25519_pub => |pk| copyOut(out, &pk.toBytes()),
                .p256 => |kp| copyOut(out, &kp.public_key.toCompressedSec1()),
                .p256_pub => |pk| copyOut(out, &pk.toCompressedSec1()),
                .p384 => |kp| copyOut(out, &kp.public_key.toCompressedSec1()),
                .p384_pub => |pk| copyOut(out, &pk.toCompressedSec1()),
            };
        }

        pub fn fromPublicBytes(alg: policy.SigAlg, raw: []const u8) Error!KeyPair {
            return switch (alg) {
                .ed25519 => .{ .inner = .{ .ed25519_pub = (Ed25519.PublicKey.fromBytes(toArr(32, raw) catch return error.OpensslFailure) catch return error.OpensslFailure) } },
                .ecdsa_p256 => .{ .inner = .{ .p256_pub = (P256.PublicKey.fromSec1(raw) catch return error.OpensslFailure) } },
                .ecdsa_p384 => .{ .inner = .{ .p384_pub = (P384.PublicKey.fromSec1(raw) catch return error.OpensslFailure) } },
                else => error.Unsupported, // RSA + P-521 + PQC are fips-only
            };
        }

        pub fn fromPrivateBytes(alg: policy.SigAlg, raw: []const u8) Error!KeyPair {
            return switch (alg) {
                .ed25519 => blk: {
                    const sk = Ed25519.SecretKey.fromBytes(toArr(64, raw) catch return error.OpensslFailure) catch return error.OpensslFailure;
                    break :blk .{ .inner = .{ .ed25519 = Ed25519.KeyPair.fromSecretKey(sk) catch return error.OpensslFailure } };
                },
                .ecdsa_p256 => blk: {
                    const sk = P256.SecretKey.fromBytes(toArr(P256.SecretKey.encoded_length, raw) catch return error.OpensslFailure) catch return error.OpensslFailure;
                    break :blk .{ .inner = .{ .p256 = P256.KeyPair.fromSecretKey(sk) catch return error.OpensslFailure } };
                },
                .ecdsa_p384 => blk: {
                    const sk = P384.SecretKey.fromBytes(toArr(P384.SecretKey.encoded_length, raw) catch return error.OpensslFailure) catch return error.OpensslFailure;
                    break :blk .{ .inner = .{ .p384 = P384.KeyPair.fromSecretKey(sk) catch return error.OpensslFailure } };
                },
                else => error.Unsupported,
            };
        }
    };

    pub fn generate(alg: policy.SigAlg) Error!KeyPair {
        var seed: [64]u8 = undefined;
        randomBytes(&seed);
        return switch (alg) {
            .ed25519 => .{ .inner = .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(seed[0..Ed25519.KeyPair.seed_length].*) catch return error.OpensslFailure } },
            .ecdsa_p256 => .{ .inner = .{ .p256 = P256.KeyPair.generateDeterministic(seed[0..P256.KeyPair.seed_length].*) catch return error.OpensslFailure } },
            .ecdsa_p384 => .{ .inner = .{ .p384 = P384.KeyPair.generateDeterministic(seed[0..P384.KeyPair.seed_length].*) catch return error.OpensslFailure } },
            else => error.Unsupported, // RSA + P-521 + PQC are fips-only
        };
    }

    pub fn sign(alg: policy.SigAlg, kp: *KeyPair, msg: []const u8, sig_out: []u8) Error!usize {
        _ = alg;
        return switch (kp.inner) {
            .ed25519 => |k| copyOut(sig_out, &(k.sign(msg, null) catch return error.OpensslFailure).toBytes()),
            .p256 => |k| copyOut(sig_out, &(k.sign(msg, null) catch return error.OpensslFailure).toBytes()),
            .p384 => |k| copyOut(sig_out, &(k.sign(msg, null) catch return error.OpensslFailure).toBytes()),
            else => error.Unsupported, // public-only keys cannot sign
        };
    }

    pub fn verify(alg: policy.SigAlg, kp: *KeyPair, msg: []const u8, sig: []const u8) Error!void {
        _ = alg;
        switch (kp.inner) {
            .ed25519 => |k| try verifyEd(k.public_key, msg, sig),
            .ed25519_pub => |pk| try verifyEd(pk, msg, sig),
            .p256 => |k| try verifyEc(P256, k.public_key, msg, sig),
            .p256_pub => |pk| try verifyEc(P256, pk, msg, sig),
            .p384 => |k| try verifyEc(P384, k.public_key, msg, sig),
            .p384_pub => |pk| try verifyEc(P384, pk, msg, sig),
        }
    }

    fn verifyEd(pk: Ed25519.PublicKey, msg: []const u8, sig: []const u8) Error!void {
        const s = Ed25519.Signature.fromBytes(toArr(64, sig) catch return error.VerifyFailed);
        s.verify(msg, pk) catch return error.VerifyFailed;
    }
    fn verifyEc(comptime S: type, pk: S.PublicKey, msg: []const u8, sig: []const u8) Error!void {
        if (sig.len != S.Signature.encoded_length) return error.VerifyFailed;
        const s = S.Signature.fromBytes(sig[0..S.Signature.encoded_length].*);
        s.verify(msg, pk) catch return error.VerifyFailed;
    }
};

pub const Kem = struct {
    pub const Error = error{ Unsupported, DecapMismatch, OpensslFailure };
    /// Same pinned named type as the fips backend.
    pub const EncapResult = struct { ct_len: usize, ss_len: usize };
    pub const KeyPair = struct {
        pub fn deinit(self: *KeyPair) void {
            _ = self;
        }
    };
    // ML-KEM + hybrids are fips-only (std has no ML-KEM).
    pub fn generate(alg: policy.KemAlg) Error!KeyPair {
        _ = alg;
        return error.Unsupported;
    }
    pub fn encapsulate(alg: policy.KemAlg, kp: *KeyPair, ct_out: []u8, ss_out: []u8) Error!EncapResult {
        _ = alg;
        _ = kp;
        _ = ct_out;
        _ = ss_out;
        return error.Unsupported;
    }
    pub fn decapsulate(alg: policy.KemAlg, kp: *KeyPair, ct: []const u8, ss_out: []u8) Error!usize {
        _ = alg;
        _ = kp;
        _ = ct;
        _ = ss_out;
        return error.Unsupported;
    }
};

pub const Csprng = struct {
    pub const Error = error{OpensslFailure};
    pub fn bytes(out: []u8) Error!void {
        randomBytes(out);
    }
};

/// No-op in the non-fips backend (there is no FIPS provider to assert).
pub fn assertActive() void {}

fn copyOut(out: []u8, src: []const u8) Sig.Error!usize {
    if (out.len < src.len) return error.OpensslFailure;
    @memcpy(out[0..src.len], src);
    return src.len;
}

fn toArr(comptime n: usize, raw: []const u8) error{BadLen}![n]u8 {
    if (raw.len != n) return error.BadLen;
    var a: [n]u8 = undefined;
    @memcpy(&a, raw[0..n]);
    return a;
}
