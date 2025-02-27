const std = @import("std");

pub const std_options: std.Options = .{
    .log_level = .warn,
};

export fn sol_compat_init(log_level: i32) void {
    _ = log_level;
}
export fn sol_compat_fini() void {}

const SolCompatFeatures = extern struct {
    struct_size: u64,
    hardcoded_features: ?[*]const u64,
    hardcoded_features_len: u64,
    supported_features: ?[*]const u64,
    supported_features_len: u64,
};

const HARDCODED_FEATURES = [_]u64{};

const SUPPORTED_FEATURES = [_]u64{
    0x0e7aa95037c5daac, // switch_to_new_elf_parser
};

const FEATURES: SolCompatFeatures = .{
    .struct_size = @sizeOf(SolCompatFeatures),
    .hardcoded_features = &HARDCODED_FEATURES,
    .hardcoded_features_len = HARDCODED_FEATURES.len,
    .supported_features = &SUPPORTED_FEATURES,
    .supported_features_len = SUPPORTED_FEATURES.len,
};

export fn sol_compat_get_features_v1() *const SolCompatFeatures {
    return &FEATURES;
}

comptime {
    _ = &@import("elf.zig");
    // _ = &@import("vm.zig");
    _ = &@import("shred_parse.zig");
}
