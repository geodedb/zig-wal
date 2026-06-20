// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! CANONICAL FIPS SEAM. Copy this file verbatim into each consumer's
//! src/, ALONGSIDE the two other canonical copy-verbatim files
//! `std_shim.zig` + `policy.zig` (Tasks 10 + 4). Call sites import THIS
//! module; never std.crypto directly in a security path.
//!
//! When -Dfips=false the backend is the local `std_shim` (zero OpenSSL
//! link, NO `fips` dependency); when -Dfips=true it is the OpenSSL FIPS
//! backend (`@import("fips")`, the only branch that pulls the lazy
//! `fips` dep). A consumer that needs RSA/PQC in NON-fips mode replaces
//! the `@import("std_shim")` below with its own backend module (which
//! may delegate to std_shim for std-covered algorithms) — see
//! docs/SEAM_CONTRACT.md.
const build_options = @import("build_options");
pub const fips_enabled = build_options.fips;
const backend = if (fips_enabled) @import("fips") else @import("std_shim");

pub const Aead = backend.Aead;
pub const Hash = backend.Hash;
pub const Mac = backend.Mac;
pub const Kdf = backend.Kdf;
pub const Sig = backend.Sig;
pub const Kem = backend.Kem;
pub const Csprng = backend.Csprng;
pub const policy = backend.policy;
pub const assertActive = backend.assertActive;
