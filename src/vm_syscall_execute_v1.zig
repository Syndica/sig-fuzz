const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const utils = @import("utils.zig");

const ManagedString = @import("protobuf").ManagedString;

const features = sig.core.features;
const executor = sig.runtime.executor;
const sysvar = sig.runtime.sysvar;
const serialize = sig.runtime.program.bpf.serialize;
const syscalls = sig.vm.syscalls;
const memory = sig.vm.memory;

const EbpfError = sig.vm.EbpfError;
const SyscallError = sig.vm.SyscallError;
const ExecutionError = sig.vm.ExecutionError;

const SbpfVersion = sig.vm.sbpf.Version;
const Vm = sig.vm.Vm;
const VmConfig = sig.vm.Config;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionInfo = sig.runtime.instruction_info.InstructionInfo;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;
const TransactionContextAccount = sig.runtime.transaction_context.TransactionContextAccount;
const FeatureSet = sig.core.FeatureSet;

const Pubkey = sig.core.Pubkey;

const convertExecutionError = sig.vm.convertExecutionError;

const EMIT_LOGS = false;

const HEAP_MAX = 256 * 1024;
const STACK_SIZE = 4_096 * 64;

export fn sol_compat_vm_cpi_syscall_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    return sol_compat_vm_syscall_execute_v1(out_ptr, out_size, in_ptr, in_size);
}

/// [fd] https://github.com/firedancer-io/firedancer/blob/b5acf851f523ec10a85e1b0c8756b2aea477107e/src/flamenco/runtime/tests/fd_exec_sol_compat.c#L744
/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/0b8a7971055d822df3f602c287c368400a784c15/src/vm_syscalls.rs#L45
export fn sol_compat_vm_syscall_execute_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});

    var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const in_slice = in_ptr[0..in_size];
    var ctx = pb.SyscallContext.decode(in_slice, allocator) catch |err| {
        std.debug.print("pb.Syscall.decode: {s}\n", .{@errorName(err)});
        return 0;
    };
    defer ctx.deinit();

    // utils.printPbSyscallContext(ctx) catch |err| {
    //     std.debug.print("printPbSyscallContext: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result = executeSyscall(allocator, ctx, EMIT_LOGS) catch |err| {
        std.debug.print("executeSyscall: {s}\n", .{@errorName(err)});
        return 0;
    };
    defer result.deinit();

    // utils.printPbSyscallEffects(result) catch |err| {
    //     std.debug.print("printPbSyscallEffects: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result_bytes = try result.encode(allocator);
    defer allocator.free(result_bytes);

    const out_slice = out_ptr[0..out_size.*];
    if (result_bytes.len > out_slice.len) {
        std.debug.print("out_slice.len: {d} < result_bytes.len: {d}\n", .{
            out_slice.len,
            result_bytes.len,
        });
        return 0;
    }
    @memcpy(out_slice[0..result_bytes.len], result_bytes);
    out_size.* = result_bytes.len;

    return 1;
}

fn executeSyscall(allocator: std.mem.Allocator, pb_syscall_ctx: pb.SyscallContext, emit_logs: bool) !pb.SyscallEffects {
    // Must have instruction context, vm context, and syscall invocation
    const pb_instr = pb_syscall_ctx.instr_ctx orelse return error.NoInstrCtx;
    const pb_vm = pb_syscall_ctx.vm_ctx orelse return error.NoVmCtx;
    const pb_syscall_invocation = pb_syscall_ctx.syscall_invocation orelse
        return error.NoSyscallInvocation;

    // // [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/0b8a7971055d822df3f602c287c368400a784c15/src/vm_syscalls.rs#L75-L87
    // for (pb_instr_ctx.accounts.items) |acc| {
    //     if (std.mem.eql(
    //         u8,
    //         acc.address.getSlice(),
    //         pb_instr_ctx.program_id.getSlice(),
    //     )) break;
    // } else {
    //     try pb_instr_ctx.accounts.append(.{
    //         .address = try pb_instr_ctx.program_id.dupe(allocator),
    //         .owner = protobuf.ManagedString.static(&(.{0} ** 32)),
    //     });
    // }

    // Create execution contexts
    var tc: TransactionContext = undefined;
    try utils.createTransactionContext(
        allocator,
        pb_instr,
        .{},
        &tc,
    );
    defer utils.deinitTransactionContext(allocator, tc);
    var syscall_registry = try sig.vm.Environment.initV1Loader(
        allocator,
        tc.feature_set,
        false,
    );
    defer syscall_registry.deinit(allocator);

    const reject_broken_elfs = true;
    const debugging_features = false;
    const direct_mapping = tc.feature_set.active.contains(
        features.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
    );
    const config = VmConfig{
        .max_call_depth = tc.compute_budget.max_call_depth,
        .stack_frame_size = tc.compute_budget.stack_frame_size,
        .enable_address_translation = true,
        .instruction_meter_checkpoint_distance = 10_000,
        .enable_instruction_meter = true,
        .enable_instruction_tracing = debugging_features,
        .enable_symbol_and_section_labels = debugging_features,
        .reject_broken_elfs = reject_broken_elfs,
        .noop_instruction_rate = 256,
        .sanitize_user_provided_values = true,
        .optimize_rodata = false,
        .aligned_memory_mapping = !direct_mapping,
        .enable_stack_frame_gaps = !direct_mapping,
        .maximum_version = .v0,
        .minimum_version = .v0,
    };

    // Set return data
    if (pb_vm.return_data) |return_data| {
        if (return_data.program_id.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
        const program_id = Pubkey{ .data = return_data.program_id.getSlice()[0..Pubkey.SIZE].* };
        tc.return_data = .{ .program_id = program_id, .data = .{} };
        try tc.return_data.data.appendSlice(return_data.data.getSlice());
    }

    // Program Cache Load Builtins??
    // https://github.com/firedancer-io/solfuzz-agave/blob/0b8a7971055d822df3f602c287c368400a784c15/src/vm_syscalls.rs#L128-L130

    // Create instruction info and push it to the transaction context
    if (pb_instr.program_id.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
    const instr_info = try utils.createInstructionInfo(
        allocator,
        &tc,
        .{ .data = pb_instr.program_id.getSlice()[0..Pubkey.SIZE].* },
        pb_instr.data.getSlice(),
        pb_instr.instr_accounts.items,
    );
    defer instr_info.deinit(allocator);

    try executor.pushInstruction(&tc, instr_info);
    const ic = try tc.getCurrentInstructionContext();

    const host_align = 16;

    const rodata = try allocator.alignedAlloc(u8, host_align, pb_vm.rodata.getSlice().len);
    defer allocator.free(rodata);
    @memcpy(rodata, pb_vm.rodata.getSlice());

    const executable: sig.vm.Executable = .{
        .instructions = &.{},
        .bytes = rodata,
        .version = .v0,
        .ro_section = .{ .borrowed = .{
            .offset = memory.RODATA_START,
            .start = 0,
            .end = rodata.len,
        } },
        .entry_pc = 0,
        .config = config,
        .text_vaddr = memory.RODATA_START,
        .function_registry = .{},
        .from_asm = false,
    };

    const mask_out_rent_epoch_in_vm_serialization = tc.feature_set.active.contains(
        features.MASK_OUT_RENT_EPOCH_IN_VM_SERIALIZATION,
    );
    var parameter_bytes, var regions, const accounts_metadata =
        try serialize.serializeParameters(
            allocator,
            ic,
            !direct_mapping,
            mask_out_rent_epoch_in_vm_serialization,
        );
    defer {
        parameter_bytes.deinit(allocator);
        regions.deinit(allocator);
    }
    tc.serialized_accounts = accounts_metadata;

    if (pb_vm.heap_max > HEAP_MAX) return error.InvalidHeapSize;

    const heap_max = @min(HEAP_MAX, pb_vm.heap_max);

    const heap = try allocator.alignedAlloc(u8, host_align, heap_max);
    defer allocator.free(heap);
    @memset(heap, 0);

    const stack = try allocator.alignedAlloc(u8, host_align, STACK_SIZE);
    defer allocator.free(stack);
    @memset(stack, 0);

    var mm_regions: std.ArrayListUnmanaged(memory.Region) = .{};
    defer mm_regions.deinit(allocator);

    try mm_regions.appendSlice(allocator, &.{
        memory.Region.init(.constant, rodata, memory.RODATA_START),
        memory.Region.initGapped(
            .mutable,
            stack,
            memory.STACK_START,
            if (config.enable_stack_frame_gaps) config.stack_frame_size else 0,
        ),
        memory.Region.init(.mutable, heap, memory.HEAP_START),
    });
    try mm_regions.appendSlice(allocator, regions.items);
    const fixture_input_region_start = mm_regions.items.len;

    var input_data_offset: u64 = 0;
    for (pb_vm.input_data_regions.items) |input_region| {
        if (input_region.content.isEmpty()) continue;

        const copy = input_region.content.getSlice();
        const duped = try allocator.alignedAlloc(u8, host_align, copy.len);
        @memcpy(duped, copy);

        if (input_region.is_writable) {
            try mm_regions.append(
                allocator,
                memory.Region.init(.mutable, duped, memory.INPUT_START + input_data_offset),
            );
        } else {
            try mm_regions.append(
                allocator,
                memory.Region.init(.constant, duped, memory.INPUT_START + input_data_offset),
            );
        }
        input_data_offset += input_region.content.getSlice().len;
    }
    defer {
        for (mm_regions.items, 0..) |region, i| {
            if (i >= fixture_input_region_start) {
                allocator.free(region.constSlice());
            }
        }
    }

    const memory_map = try memory.MemoryMap.init(
        allocator,
        mm_regions.items,
        .v0,
        config,
    );

    var vm = try Vm.init(
        allocator,
        &executable,
        memory_map,
        &syscall_registry,
        stack.len,
        &tc,
    );
    defer vm.deinit();

    // r0 is the return value register
    // r1-5 are the argument registers
    // r6-11 aren't used by the syscalls
    vm.registers.set(.r0, 0);
    vm.registers.set(.r1, pb_vm.r1);
    vm.registers.set(.r2, pb_vm.r2);
    vm.registers.set(.r3, pb_vm.r3);
    vm.registers.set(.r4, pb_vm.r4);
    vm.registers.set(.r5, pb_vm.r5);

    utils.copyPrefix(heap, pb_syscall_invocation.heap_prefix.getSlice());
    utils.copyPrefix(stack, pb_syscall_invocation.stack_prefix.getSlice());

    const syscall_name = pb_syscall_ctx.syscall_invocation.?.function_name.getSlice();
    const syscall_entry = syscall_registry.lookupName(syscall_name) orelse {
        std.debug.print("Syscall not found: {s}\n", .{syscall_name});
        return error.SyscallNotFound;
    };
    const syscall_fn = syscall_entry.value;

    var execution_error: ?sig.vm.ExecutionError = null;
    syscall_fn(&tc, &vm.memory_map, &vm.registers) catch |err| {
        execution_error = err;
    };

    try executor.popInstruction(&tc);

    var @"error": i64, var error_kind: pb.ErrKind = .{ 0, .UNSPECIFIED };
    if (execution_error) |err| {
        const e, const ek, const msg = convertExecutionError(err);
        @"error" = e;
        error_kind = switch (ek) {
            .Instruction => .INSTRUCTION,
            .Syscall => .SYSCALL,
            .Ebpf => .EBPF,
        };
        // Agave doesn't log Poseidon errors
        if (e != -1) {
            try sig.runtime.stable_log.programFailure(&tc, instr_info.program_meta.pubkey, msg);
        }
    }

    const effects = try utils.createSyscallEffect(allocator, .{
        .tc = &tc,
        .err = @"error",
        .err_kind = error_kind,
        .heap = heap,
        .stack = stack,
        .rodata = rodata,
        .frame_count = vm.depth,
        .memory_map = vm.memory_map,
        .registers = blk: {
            var registers = sig.vm.interpreter.RegisterMap.initFill(0);
            if (execution_error == null) registers.set(.r0, vm.registers.get(.r0));
            break :blk registers;
        },
    });

    if (emit_logs) {
        std.debug.print("Execution Logs:\n", .{});
        for (tc.log_collector.?.collect(), 1..) |msg, index| {
            std.debug.print("    {}: {s}\n", .{ index, msg });
        }
    }

    return effects;
}
