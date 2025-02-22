const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const protobuf = @import("protobuf");
const sig = @import("sig");

const Shred = sig.ledger.shred.Shred;
const ShredBinary = pb.ShredBinary;
const AcceptsShred = pb.AcceptsShred;

export fn sol_compat_shred_parse_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const in_slice = in_ptr[0..in_size];
    const shred_binary = try ShredBinary.decode(in_slice, allocator);
    defer shred_binary.deinit();

    var result: AcceptsShred = .{ .valid = std.meta.isError(
        Shred.fromPayload(allocator, shred_binary.data.getSlice()),
    ) };

    const result_bytes = try result.encode(allocator);
    defer result.deinit();

    const out_slice = out_ptr[0..out_size.*];
    if (result_bytes.len > out_slice.len) {
        return 0;
    }
    @memcpy(out_slice[0..result_bytes.len], result_bytes);
    out_size.* = result_bytes.len;
    return 1;
}
