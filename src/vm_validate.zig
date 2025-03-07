const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const protobuf = @import("protobuf");
const sig = @import("sig");

const svm = sig.svm;
const FullVmContext = pb.FullVmContext;
const VmContext = pb.VmContext;
const ValidateVmEffects = pb.ValidateVmEffects;

export fn sol_compat_vm_validate_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});
    // var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 100 }){};
    // const allocator = gpa.allocator();
    // defer _ = gpa.deinit();
    const allocator = std.heap.c_allocator;

    // zig_protobuf leaks sometimes on invalid input, so we just work around with
    // by using an arena
    var decode_arena = std.heap.ArenaAllocator.init(allocator);
    defer decode_arena.deinit();

    const in_slice = in_ptr[0..in_size];
    const ctx = FullVmContext.decode(in_slice, decode_arena.allocator()) catch return 0;
    defer ctx.deinit();

    const vm_ctx = ctx.vm_ctx orelse return 0;
    const features: pb.FeatureSet = ctx.features orelse .{
        .features = std.ArrayList(u64).init(allocator),
    };

    const result = validateVmText(allocator, vm_ctx, features) catch return 0;
    const result_bytes = try result.encode(allocator);
    defer allocator.free(result_bytes);

    const out_slice = out_ptr[0..out_size.*];
    if (result_bytes.len > out_slice.len) {
        return 0;
    }
    @memcpy(out_slice[0..result_bytes.len], result_bytes);
    out_size.* = result_bytes.len;
    return 1;
}

fn validateVmText(
    allocator: std.mem.Allocator,
    vm_ctx: VmContext,
    feature_set: pb.FeatureSet,
) !ValidateVmEffects {
    const text_len = vm_ctx.rodata_text_section_length;
    const text_offset = vm_ctx.rodata_text_section_offset;

    const rodata = vm_ctx.rodata.getSlice();
    const bytes = safeSlice(rodata, text_offset, text_len) catch {
        return .{
            .result = -36, // Firedancer's error code for invalid text section
            .success = false,
        };
    };

    var loader: svm.BuiltinProgram = .{};
    defer loader.deinit(allocator);

    var function_registery: svm.Registry(u64) = .{};
    errdefer function_registery.deinit(allocator);

    var feature_map: std.AutoHashMapUnmanaged(u64, void) = .{};
    defer feature_map.deinit(allocator);
    for (feature_set.features.items) |feat| {
        try feature_map.put(allocator, feat, {});
    }

    const min_version: svm.sbpf.Version = if (!feature_map.contains(0x1db51f609c8fcd07) or
        feature_map.contains(0xe5937c9dd5edd306))
        .v0
    else
        .v3;

    const max_version: svm.sbpf.Version = if (feature_map.contains(0xbec08bda942c5ea5))
        .v3
    else if (feature_map.contains(0x408e6a8a269a6ad1))
        .v2
    else if (feature_map.contains(0xefc2cb9c2b40f3ff))
        .v1
    else
        .v0;

    var executable = try svm.Executable.fromTextBytes(
        allocator,
        bytes,
        &loader,
        &function_registery,
        // false, TODO: re-enable when the validation PR is merged
        .{
            .minimum_version = min_version,
            .maximum_version = max_version,
        },
    );
    defer executable.deinit(allocator);

    const result = if (executable.verify(&loader))
        0
    else |err|
        fdErrCode(err);

    return .{
        .result = result,
        .success = result == 0,
    };
}

fn fdErrCode(err: anyerror) i32 {
    // https://github.com/firedancer-io/firedancer/blob/f878e448e5511c3600e2dd6360a4f06ce793af6f/src/flamenco/vm/fd_vm_base.h#L67
    return switch (err) {
        error.NoProgram => -6,
        error.DivisionByZero => -18,
        error.UnknownInstruction => -25,
        error.InvalidSourceRegister => -26,
        error.InvalidDestinationRegister => -27,
        error.CannotWriteR10 => -27,
        error.JumpOutOfCode => -29,
        error.JumpToMiddleOfLddw => -30,
        error.UnsupportedLEBEArgument => -31,
        error.LddwCannotBeLast => -32,
        error.IncompleteLddw => -33,
        error.InvalidRegister => -35,
        error.ShiftWithOverflow => -37,
        error.ProgramLengthNotMultiple => -38,
        else => -1,
    };
}

fn safeSlice(base: anytype, start: usize, len: usize) error{OutOfBounds}!@TypeOf(base) {
    if (start > base.len) return error.OutOfBounds;
    if (len == 0) return &.{};
    const end = std.math.add(usize, start, len) catch return error.OutOfBounds;
    if (end > base.len) return error.OutOfBounds;
    return base[start..][0..len];
}
