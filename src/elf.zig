const std = @import("std");
const sig = @import("sig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const protobuf = @import("protobuf");

const ELFLoaderCtx = pb.ELFLoaderCtx;
const ElfLoaderEffects = pb.ELFLoaderEffects;

const svm = sig.svm;
const syscalls = svm.syscalls;
const Elf = svm.Elf;
const Executable = svm.Executable;
const Config = svm.Config;
const memory = svm.memory;
const BuiltinProgram = svm.BuiltinProgram;
const Vm = svm.Vm;
const Registry = svm.Registry;
const Instruction = svm.sbpf.Instruction;

export fn sol_compat_init(log_level: i32) void {
    _ = log_level;
}
export fn sol_compat_fini() void {}

export fn sol_compat_elf_loader_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});
    const allocator = std.heap.c_allocator;

    const in_slice: []const u8 = in_ptr[0..in_size];
    const ctx = ELFLoaderCtx.decode(in_slice, allocator) catch return 0;
    const ctx_elf = ctx.elf orelse return 0;
    const elf_bytes = ctx_elf.data.getSlice();

    var elf_effects: ElfLoaderEffects = .{
        .calldests = std.ArrayList(u64).init(allocator),
    };
    var loader: BuiltinProgram = .{};

    inline for (.{
        .{ "sol_log_", syscalls.log },
        .{ "sol_log_64_", syscalls.log64 },
        .{ "sol_log_pubkey", syscalls.logPubkey },
        .{ "sol_log_compute_units_", syscalls.logComputeUnits },
        .{ "sol_memset_", syscalls.memset },
        .{ "sol_memcpy_", syscalls.memcpy },
        .{ "abort", syscalls.abort },
    }) |entry| {
        const name, const function = entry;
        _ = try loader.functions.registerHashed(
            allocator,
            name,
            function,
        );
    }

    const config: Config = .{
        .maximum_version = .v0,
        .minimum_version = .v0,
        .optimize_rodata = false,
    };
    const duped_elf_bytes = try allocator.dupe(u8, elf_bytes[0..ctx.elf_sz]);

    const output_file = try std.fs.cwd().createFile("out.so", .{});
    try output_file.writeAll(duped_elf_bytes);
    output_file.close();

    var elf = Elf.parse(allocator, duped_elf_bytes, &loader, config) catch {
        return try encode(elf_effects, allocator, out_ptr, out_size);
    };
    const executable = Executable.fromElf(elf) catch return 0;

    const ro_data = switch (executable.ro_section) {
        .owned => |o| o.data,
        .borrowed => |a| executable.bytes[a.start..a.end],
    };
    const text_bytes_index = elf.getShdrIndexByName(".text").?;
    const text_bytes = try elf.headers.shdrSlice(text_bytes_index);
    elf_effects.rodata = try protobuf.ManagedString.copy(ro_data, allocator);
    elf_effects.rodata_sz = ro_data.len;
    elf_effects.entry_pc = executable.entry_pc;
    elf_effects.text_off = executable.text_vaddr - memory.RODATA_START;
    elf_effects.text_cnt = text_bytes.len / 8;

    var map_iter = executable.function_registry.map.iterator();
    var calldests: std.AutoHashMapUnmanaged(u64, void) = .{};
    defer calldests.deinit(allocator);
    while (map_iter.next()) |entry| {
        const fn_addr = entry.value_ptr.value;
        try calldests.put(allocator, fn_addr, {});
    }
    var iter = calldests.keyIterator();
    while (iter.next()) |key| {
        try elf_effects.calldests.append(key.*);
    }
    std.sort.heap(u64, elf_effects.calldests.items, {}, std.sort.asc(u64));

    return try encode(elf_effects, allocator, out_ptr, out_size);
}

fn encode(
    effect: ElfLoaderEffects,
    allocator: std.mem.Allocator,
    out_ptr: [*]u8,
    out_size: *u64,
) !i32 {
    const effect_bytes = try effect.encode(allocator);
    const out_slice = out_ptr[0..out_size.*];
    if (effect_bytes.len > out_slice.len) {
        return 0;
    }
    @memcpy(out_slice[0..effect_bytes.len], effect_bytes);
    out_size.* = effect_bytes.len;
    return 1;
}
