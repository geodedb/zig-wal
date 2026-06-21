<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# FIPS-140-3 Mode (`-Dfips`)

## Flag semantics

`wal` builds with a `-Dfips` flag (default `false`). When **off**, security
crypto routes through `src/std_shim.zig` (pure `std.crypto`) with zero overhead,
no `fips` dependency, and no OpenSSL link. When **on**
(`-Dfips=true -Dopenssl_path=<prefix>`), the same call sites route through the
linked OpenSSL 3.x FIPS-140-3 provider via the lazy `fips` package, and
`crypto_backend.assertActive()` hard-fails if the validated provider is absent.

```sh
zig build test --summary all && zig build test-integration --summary all
OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf zig build test -Dfips=true -Dopenssl_path=/usr/local/ssl --summary all
# or:  make test-dual
```

`-Dfips` is added to the SAME single `build_options` instance as the otel seam
(GAP-0020-safe; both seams proven green together). The seam module is carried on
the `Deps` struct and threaded via `createRootModule` into every compile unit.

## Routed (security) call sites

| Site | Primitive | Seam call |
|------|-----------|-----------|
| `src/encryption.zig` `encryptRecord` nonce | record nonce CSPRNG | `crypto_backend.Csprng.bytes` |
| `src/encryption.zig` `encryptInto` nonce | record nonce CSPRNG | `crypto_backend.Csprng.bytes` |
| `src/encryption.zig` `encryptRecord` / `encryptInto` | record AES-256-GCM seal | `crypto_backend.Aead.seal(.aes_256_gcm, …)` |
| `src/encryption.zig` `decryptRecord` | record AES-256-GCM open | `crypto_backend.Aead.open(.aes_256_gcm, …)` |
| `src/encryption.zig` `decryptRecordInPlace` | record AES-256-GCM open (in-place) | `crypto_backend.Aead.open(.aes_256_gcm, …)` |

For `decryptRecordInPlace`, the ciphertext is `copyForwards`-moved to the front
of the buffer and then decrypted fully in-place (in == out at the same offset),
which both the std and OpenSSL EVP backends support, preserving the no-heap-alloc
contract.

## `fips-exempt` (allow-listed non-security) uses

| Site | Reason |
|------|--------|
| `src/encryption.zig` `Aes256Gcm` alias | compile-time nonce/tag sizes only; the AEAD goes through the seam |
| `src/record.zig` `Crc32IsoHdlc` | CRC32 record framing checksum, not adversary-resistant integrity (AES-GCM tag covers that) |

## Behavior changes / removals under `-Dfips=true`

None. WAL on-disk record format (`blob_len || magic || nonce || tag || ciphertext`)
is byte-compatible across both modes (AES-256-GCM in both backends).
