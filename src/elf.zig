const std = @import("std");
const sig = @import("sig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const protobuf = @import("protobuf");

const ELFLoaderCtx = pb.ELFLoaderCtx;
const ElfLoaderEffects = pb.ELFLoaderEffects;

const svm = sig.vm;
const syscalls = svm.syscalls;
const Elf = svm.Elf;
const Executable = svm.Executable;
const Config = svm.Config;
const memory = svm.memory;
const BuiltinProgram = svm.BuiltinProgram;
const Vm = svm.Vm;
const Registry = svm.Registry;
const Instruction = svm.sbpf.Instruction;

export fn sol_compat_elf_loader_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});
    const allocator = std.heap.c_allocator;
    // var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 100 }){};
    // defer _ = gpa.deinit();
    // const allocator = gpa.allocator();

    const in_slice: []const u8 = in_ptr[0..in_size];

    // zig_protobuf leaks sometimes on invalid input, so we just work around with
    // by using an arena
    var decode_arena = std.heap.ArenaAllocator.init(allocator);
    defer decode_arena.deinit();

    const ctx = ELFLoaderCtx.decode(in_slice, decode_arena.allocator()) catch return 0;
    defer ctx.deinit();

    const elf_effects = executeElfTest(ctx, allocator) catch return 0;
    defer elf_effects.deinit();

    return try encode(elf_effects, allocator, out_ptr, out_size);
}

fn executeElfTest(ctx: ELFLoaderCtx, allocator: std.mem.Allocator) !ElfLoaderEffects {
    const ctx_elf = ctx.elf orelse return error.Unknown;
    const elf_bytes = ctx_elf.data.getSlice();
    if (elf_bytes.len != ctx.elf_sz) return error.Unknown;

    var elf_effects: ElfLoaderEffects = .{
        .calldests = std.ArrayList(u64).init(allocator),
    };

    var loader: BuiltinProgram = .{};
    defer loader.deinit(allocator);

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

    const duped_elf_bytes = try allocator.alloc(u8, ctx.elf_sz);
    @memset(duped_elf_bytes, 0);
    @memcpy(duped_elf_bytes.ptr, elf_bytes[0..@min(elf_bytes.len, ctx.elf_sz)]);
    defer allocator.free(duped_elf_bytes);

    // const output_file = try std.fs.cwd().createFile("out.so", .{});
    // try output_file.writeAll(duped_elf_bytes);
    // output_file.close();

    var elf = Elf.parse(allocator, duped_elf_bytes, &loader, config) catch {
        return elf_effects;
    };
    errdefer elf.deinit(allocator);

    var executable = Executable.fromElf(elf);
    defer executable.deinit(allocator);

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

    return elf_effects;
}

fn encode(
    effect: ElfLoaderEffects,
    allocator: std.mem.Allocator,
    out_ptr: [*]u8,
    out_size: *u64,
) !i32 {
    const effect_bytes = try effect.encode(allocator);
    defer allocator.free(effect_bytes);
    const out_slice = out_ptr[0..out_size.*];
    if (effect_bytes.len > out_slice.len) {
        return 0;
    }
    @memcpy(out_slice[0..effect_bytes.len], effect_bytes);
    out_size.* = effect_bytes.len;
    return 1;
}
