const std = @import("std");
const sig = @import("sig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const protobuf = @import("protobuf");

const SyscallContext = pb.SyscallContext;

const svm = sig.vm;
const syscalls = svm.syscalls;
const Elf = svm.Elf;
const Executable = svm.Executable;
const Config = svm.Config;
const memory = svm.memory;
const BuiltinProgram = svm.BuiltinProgram;
const Region = memory.Region;
const Vm = svm.Vm;
const Registry = svm.Registry;
const Instruction = svm.sbpf.Instruction;
const Version = svm.sbpf.Version;

const HEAP_MAX = 256 * 1024;
const STACK_SIZE = 4_096 * 64;

// NOTE: This totally doesn't work, just for fun and testing!
export fn sol_compat_vm_interp_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});
    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = gpa.deinit();
    // const allocator = gpa.allocator();
    const allocator = std.heap.c_allocator;

    const in_slice = in_ptr[0..in_size];
    const syscall_context = try SyscallContext.decode(in_slice, allocator);
    defer syscall_context.deinit();

    const result = executeVmTest(syscall_context, allocator) catch {
        return 0;
    };
    defer result.deinit();

    const elf_effect_bytes = try result.encode(allocator);
    defer allocator.free(elf_effect_bytes);

    const out_slice = out_ptr[0..out_size.*];
    if (elf_effect_bytes.len > out_slice.len) {
        return 0;
    }
    @memcpy(out_slice[0..elf_effect_bytes.len], elf_effect_bytes);
    out_size.* = elf_effect_bytes.len;
    return 1;
}

fn executeVmTest(
    syscall_context: SyscallContext,
    allocator: std.mem.Allocator,
) !pb.SyscallEffects {
    const config: Config = .{ .minimum_version = .v1 };
    const vm_ctx = syscall_context.vm_ctx.?;
    const rodata_slice = vm_ctx.rodata.getSlice();
    const version: Version = @enumFromInt(vm_ctx.sbpf_version);
    if (version != .v1) return error.SupportThisVersion;

    const function_registry: Registry(u64) = .{};
    var loader: BuiltinProgram = .{};

    if (rodata_slice.len % @sizeOf(Instruction) != 0) return error.InvalidInput;
    var executable: Executable = .{
        .instructions = std.mem.bytesAsSlice(Instruction, rodata_slice),
        .bytes = rodata_slice,
        .version = version,
        .ro_section = .{ .borrowed = .{
            .offset = memory.RODATA_START,
            .start = 0,
            .end = rodata_slice.len,
        } },
        .entry_pc = vm_ctx.entry_pc,
        .config = config,
        .text_vaddr = memory.RODATA_START,
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
    defer regions.deinit(allocator);

    try regions.appendSlice(allocator, &.{
        Region.init(.constant, vm_ctx.rodata.getSlice(), memory.RODATA_START),
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
            const duped = try allocator.dupe(u8, input_region.content.getSlice());
            try regions.append(
                allocator,
                Region.init(.constant, duped, memory.INPUT_START + input_data_offset),
            );
        }
        input_data_offset += input_region.content.getSlice().len;
    }
    defer {
        for (regions.items) |region| {
            if (region.vm_addr_start >= memory.INPUT_START) {
                // the function does not return errors for `.constant` accesses
                const slice = region.getSlice(.constant) catch unreachable;
                allocator.free(slice);
            }
        }
    }

    const map = try memory.MemoryMap.init(regions.items, version);
    var vm = try Vm.init(allocator, &executable, map, &loader, stack.len);
    defer vm.deinit();

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
        .heap = protobuf.ManagedString.move(heap, allocator),
        .stack = protobuf.ManagedString.move(stack, allocator),
        .rodata = try protobuf.ManagedString.copy(rodata_slice, allocator),
        .input_data_regions = std.ArrayList(pb.InputDataRegion).init(allocator),
        .pc = vm.registers.get(.r11),
    };
}
