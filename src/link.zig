// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Canonical OpenSSL linking helper. Reused verbatim by every consumer
//! build.zig that links the fips backend, so the include/lib paths and
//! platform branches stay in one place.
const std = @import("std");

/// Link libcrypto + libssl onto `m`. When `openssl_path` is non-null it
/// is treated as an install prefix (`<prefix>/include`, `<prefix>/lib`,
/// `<prefix>/lib64`); otherwise the system libraries are used. On
/// Windows a VCPKG_ROOT include path is added when present (mirrors
/// tls/build.zig:982-986).
pub fn linkOpenssl(b: *std.Build, m: *std.Build.Module, openssl_path: ?[]const u8) void {
    const os_tag = m.resolved_target.?.result.os.tag;
    if (openssl_path) |p| {
        m.addIncludePath(.{ .cwd_relative = b.fmt("{s}/include", .{p}) });
        // Most x86_64 OpenSSL installs use lib64; some use lib. Both are
        // added (a missing one only yields a benign linker warning).
        m.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/lib64", .{p}) });
        m.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/lib", .{p}) });
        // RPATH the prefix libdirs so the FIPS-build libcrypto (which has
        // the fips.so provider in its compiled-in MODULESDIR) is the one
        // loaded at RUNTIME — not a system libcrypto that lacks the FIPS
        // provider config. Without this the binary links fine but
        // OSSL_PROVIDER_load(ctx, "fips") fails because the system
        // libcrypto resolves first on the loader path.
        if (os_tag != .windows) {
            m.addRPath(.{ .cwd_relative = b.fmt("{s}/lib64", .{p}) });
            m.addRPath(.{ .cwd_relative = b.fmt("{s}/lib", .{p}) });
        }
    } else if (os_tag == .windows) {
        if (b.graph.environ_map.get("VCPKG_ROOT")) |root| {
            m.addIncludePath(.{ .cwd_relative = b.fmt("{s}/installed/x64-windows/include", .{root}) });
            m.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/installed/x64-windows/lib", .{root}) });
        }
    } else if (os_tag == .macos) {
        // Homebrew openssl@3 keg-only prefix.
        m.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        m.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
    }
    m.linkSystemLibrary("ssl", .{});
    m.linkSystemLibrary("crypto", .{});
    m.link_libc = true;
}
