const std = @import("std");
const backend = @import("std_shim");

test "OS entropy fills buffers and accepts empty requests" {
    var empty: [0]u8 = .{};
    try backend.Csprng.bytes(&empty);
    var first: [64]u8 = undefined;
    var second: [64]u8 = undefined;
    try backend.Csprng.bytes(&first);
    try backend.Csprng.bytes(&second);
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
}

test "OS entropy supports Ed25519 and ECDSA key generation" {
    for ([_]backend.policy.SigAlg{ .ed25519, .ecdsa_p256, .ecdsa_p384 }) |algorithm| {
        var key = try backend.Sig.generate(algorithm);
        defer key.deinit();
        var public_bytes: [128]u8 = undefined;
        const public_len = try key.publicBytes(&public_bytes);
        var public_key = try backend.Sig.KeyPair.fromPublicBytes(algorithm, public_bytes[0..public_len]);
        defer public_key.deinit();
        var signature: [128]u8 = undefined;
        const n = try backend.Sig.sign(algorithm, &key, "portable entropy", &signature);
        try backend.Sig.verify(algorithm, &public_key, "portable entropy", signature[0..n]);
        try std.testing.expectError(error.VerifyFailed, backend.Sig.verify(algorithm, &public_key, "different message", signature[0..n]));
    }
}
