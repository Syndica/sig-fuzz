const std = @import("std");
const sig = @import("sig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const protobuf = @import("protobuf");

const ELFLoaderCtx = pb.ELFLoaderCtx;
const ElfLoaderEffects = pb.ELFLoaderEffects;
const syscalls = sig.svm.syscalls;
const Elf = sig.svm.Elf;
const Executable = sig.svm.Executable;
const Config = sig.svm.Config;
const memory = sig.svm.memory;
const BuiltinProgram = sig.svm.BuiltinProgram;

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
        .minimum_version = .v1,
        .optimize_rodata = false,
    };
    const duped_elf_bytes = try allocator.dupe(u8, elf_bytes[0..ctx.elf_sz]);

    const output_file = try std.fs.cwd().createFile("out.so", .{});
    try output_file.writeAll(duped_elf_bytes);
    output_file.close();

    var elf = Elf.parse(allocator, duped_elf_bytes, &loader, config) catch {
        return 0;
    };
    const executable = Executable.fromElf(allocator, &elf) catch {
        return 0;
    };

    const ro_data = switch (executable.ro_section) {
        .owned => |o| o.data,
        .borrowed => |a| executable.bytes[a.start..a.end],
    };

    const text_bytes_index = elf.data.getShdrIndexByName(elf.headers, ".text").?;
    const text_bytes = try elf.headers.shdrSlice(text_bytes_index);
    elf_effects.rodata = try protobuf.ManagedString.copy(ro_data, allocator);
    elf_effects.rodata_sz = ro_data.len;
    elf_effects.entry_pc = executable.entry_pc;
    elf_effects.text_off = executable.text_vaddr - memory.PROGRAM_START;
    elf_effects.text_cnt = text_bytes.len / 8;

    var iter = executable.function_registry.map.iterator();
    while (iter.next()) |entry| {
        const fn_addr = entry.value_ptr.value;
        try elf_effects.calldests.append(fn_addr);
    }
    std.sort.heap(u64, elf_effects.calldests.items, {}, std.sort.asc(u64));

    const elf_effect_bytes = try elf_effects.encode(allocator);
    const out_slice = out_ptr[0..out_size.*];
    if (elf_effect_bytes.len > out_slice.len) {
        return 0;
    }
    @memcpy(out_slice[0..elf_effect_bytes.len], elf_effect_bytes);
    out_size.* = elf_effect_bytes.len;
    return 1;
}
