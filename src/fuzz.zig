const std = @import("std");
const sig = @import("sig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const protobuf = @import("protobuf");

const ELFLoaderCtx = pb.ELFLoaderCtx;
const ElfLoaderEffects = pb.ELFLoaderEffects;
const SyscallContext = pb.SyscallContext;

const syscalls = sig.svm.syscalls;
const Elf = sig.svm.Elf;
const Executable = sig.svm.Executable;
const Config = sig.svm.Config;
const memory = sig.svm.memory;
const BuiltinProgram = sig.svm.BuiltinProgram;
const Region = memory.Region;
const Vm = sig.svm.Vm;
const Registry = sig.svm.Registry;
const Instruction = sig.svm.sbpf.Instruction;

const HEAP_MAX = 256 * 1024;
const STACK_SIZE = 4_096 * 64;

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

export fn sol_compat_vm_interp_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});
    const allocator = std.heap.c_allocator;

    const in_slice = in_ptr[0..in_size];
    const syscall_context = try SyscallContext.decode(in_slice, allocator);

    const result = executeVmTest(syscall_context) catch {
        return 0;
    };

    const elf_effect_bytes = try result.encode(allocator);
    const out_slice = out_ptr[0..out_size.*];
    if (elf_effect_bytes.len > out_slice.len) {
        return 0;
    }
    @memcpy(out_slice[0..elf_effect_bytes.len], elf_effect_bytes);
    out_size.* = elf_effect_bytes.len;
    return 1;
}

fn executeVmTest(syscall_context: SyscallContext) !pb.SyscallEffects {
    const allocator = std.heap.c_allocator;
    const config: Config = .{ .minimum_version = .v1 };
    const vm_ctx = syscall_context.vm_ctx.?;
    const rodata_slice = vm_ctx.rodata.getSlice();
    const version: sig.svm.SBPFVersion = @enumFromInt(vm_ctx.sbpf_version);
    if (version != .v1) return error.SupportThisVersion;

    const function_registry: Registry(u64) = .{};
    var loader: BuiltinProgram = .{};

    if (rodata_slice.len % @sizeOf(Instruction) != 0) return error.InvalidInput;
    var executable: Executable = .{
        .instructions = std.mem.bytesAsSlice(Instruction, rodata_slice),
        .bytes = rodata_slice,
        .version = version,
        .ro_section = .{ .borrowed = .{
            .offset = memory.PROGRAM_START,
            .start = 0,
            .end = rodata_slice.len,
        } },
        .entry_pc = vm_ctx.entry_pc,
        .config = config,
        .text_vaddr = memory.PROGRAM_START,
        .function_registry = function_registry,
        .from_elf = false,
    };

    const heap_max = @min(HEAP_MAX, vm_ctx.heap_max);
    const syscall_inv = syscall_context.syscall_invocation.?;

    const heap = try allocator.alloc(u8, heap_max);
    const stack = try allocator.alloc(u8, STACK_SIZE);

    std.mem.copyForwards(u8, heap, syscall_inv.heap_prefix.getSlice());
    std.mem.copyForwards(u8, stack, syscall_inv.stack_prefix.getSlice());

    var regions: std.ArrayListUnmanaged(Region) = .{};
    try regions.appendSlice(allocator, &.{
        Region.init(.constant, vm_ctx.rodata.getSlice(), memory.PROGRAM_START),
        Region.init(.mutable, stack, memory.STACK_START),
        Region.init(.mutable, heap, memory.HEAP_START),
    });

    var input_data_offset: u64 = 0;
    for (vm_ctx.input_data_regions.items) |input_region| {
        if (input_region.content.isEmpty()) continue;
        if (input_region.is_writable) {
            const mutable = try allocator.dupe(u8, input_region.content.getSlice());
            try regions.append(
                allocator,
                Region.init(.mutable, mutable, memory.INPUT_START + input_data_offset),
            );
        } else {
            try regions.append(
                allocator,
                Region.init(
                    .constant,
                    input_region.content.getSlice(),
                    memory.INPUT_START + input_data_offset,
                ),
            );
        }
        input_data_offset += input_region.content.getSlice().len;
    }

    const map = try memory.MemoryMap.init(regions.items, version);
    var vm = try Vm.init(allocator, &executable, map, &loader, stack.len);

    vm.registers.set(.r0, vm_ctx.r0);
    vm.registers.set(.r1, vm_ctx.r1);
    vm.registers.set(.r2, vm_ctx.r2);
    vm.registers.set(.r3, vm_ctx.r3);
    vm.registers.set(.r4, vm_ctx.r4);
    vm.registers.set(.r5, vm_ctx.r5);
    vm.registers.set(.r6, vm_ctx.r6);
    vm.registers.set(.r7, vm_ctx.r7);
    vm.registers.set(.r8, vm_ctx.r8);
    vm.registers.set(.r9, vm_ctx.r9);

    const result = vm.run();
    const out_registers: [12]u64 = if (std.meta.isError(result))
        .{0} ** 12
    else
        vm.registers.values[0..12].*;

    return .{
        .@"error" = if (result) |_| 0 else |err| switch (err) {
            error.DivisionByZero => 18,
            error.UnknownInstruction => 12,
            else => -1,
        },
        .r0 = out_registers[0],
        .r1 = out_registers[1],
        .r2 = out_registers[2],
        .r3 = out_registers[3],
        .r4 = out_registers[4],
        .r5 = out_registers[5],
        .r6 = out_registers[6],
        .r7 = out_registers[7],
        .r8 = out_registers[8],
        .r9 = out_registers[9],
        .r10 = out_registers[10],
        .frame_count = vm.depth,
        .heap = try protobuf.ManagedString.copy(heap, allocator),
        .stack = try protobuf.ManagedString.copy(stack, allocator),
        .rodata = try protobuf.ManagedString.copy(rodata_slice, allocator),
        .input_data_regions = std.ArrayList(pb.InputDataRegion).init(allocator),
        .pc = vm.registers.get(.r11),
    };
}
