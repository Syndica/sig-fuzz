const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const utils = @import("utils.zig");

const ManagedString = @import("protobuf").ManagedString;

const features = sig.runtime.features;
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

const Pubkey = sig.core.Pubkey;

const EMIT_LOGS = false;

const HEAP_MAX = 256 * 1024;
const STACK_SIZE = 4_096 * 64;

/// [fd] https://github.com/firedancer-io/firedancer/blob/b5acf851f523ec10a85e1b0c8756b2aea477107e/src/flamenco/runtime/tests/fd_exec_sol_compat.c#L744
/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/0b8a7971055d822df3f602c287c368400a784c15/src/vm_syscalls.rs#L45
export fn sol_compat_vm_syscall_execute_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});
    const allocator = std.heap.c_allocator;

    var decode_arena = std.heap.ArenaAllocator.init(allocator);
    defer decode_arena.deinit();

    const in_slice = in_ptr[0..in_size];
    var ctx = pb.SyscallContext.decode(
        in_slice,
        decode_arena.allocator(),
    ) catch |err| {
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
    const ec, const sc, const tc = try utils.createExecutionContexts(
        allocator,
        pb_instr,
    );
    defer {
        ec.deinit();
        allocator.destroy(ec);
        sc.deinit();
        allocator.destroy(sc);
        tc.deinit();
        allocator.destroy(tc);
    }

    const syscall_registry = try sig.vm.syscalls.register(
        allocator,
        &ec.feature_set,
        (try sc.sysvar_cache.get(sysvar.Clock)).slot,
        false,
    );
    defer syscall_registry.deinit(allocator);

    const reject_broken_elfs = true;
    const debugging_features = false;
    const direct_mapping = ec.feature_set.isActive(
        features.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
        0,
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
        tc,
        .{ .data = pb_instr.program_id.getSlice()[0..Pubkey.SIZE].* },
        pb_instr.data.getSlice(),
        pb_instr.instr_accounts.items,
    );
    defer instr_info.deinit(allocator);

    try executor.pushInstruction(tc, instr_info);
    const ic = try tc.getCurrentInstructionContext();

    const rodata = try allocator.dupe(u8, pb_vm.rodata.getSlice());
    defer allocator.free(rodata);

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

    const parameter_bytes, const regions, const accounts_metadata =
        try serialize.serializeParameters(
            allocator,
            ic,
            !direct_mapping,
        );
    defer {
        allocator.free(parameter_bytes);
        allocator.free(regions);
    }
    tc.serialized_accounts = accounts_metadata;

    if (pb_vm.heap_max > HEAP_MAX) return error.InvalidHeapSize;

    const heap_max = @min(HEAP_MAX, pb_vm.heap_max);

    const heap = try allocator.alloc(u8, heap_max);
    defer allocator.free(heap);
    @memset(heap, 0);

    const stack = try allocator.alloc(u8, STACK_SIZE);
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
    try mm_regions.appendSlice(allocator, regions);
    const fixture_input_region_start = mm_regions.items.len;

    var input_data_offset: u64 = 0;
    for (pb_vm.input_data_regions.items) |input_region| {
        if (input_region.content.isEmpty()) continue;
        if (input_region.is_writable) {
            const mutable = try allocator.dupe(u8, input_region.content.getSlice());
            try mm_regions.append(
                allocator,
                memory.Region.init(.mutable, mutable, memory.INPUT_START + input_data_offset),
            );
        } else {
            const duped = try allocator.dupe(u8, input_region.content.getSlice());
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
        tc,
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
    const syscall_entry = syscall_registry.functions.lookupName(syscall_name) orelse {
        std.debug.print("Syscall not found: {s}\n", .{syscall_name});
        return error.SyscallNotFound;
    };
    const syscall_fn = syscall_entry.value;

    var execution_error: ?sig.vm.ExecutionError = null;
    syscall_fn(tc, &vm.memory_map, &vm.registers) catch |err| {
        execution_error = err;
    };

    try executor.popInstruction(tc);

    var @"error": i64, var error_kind: pb.ErrKind = .{ 0, .UNSPECIFIED };
    if (execution_error) |err| {
        const e, const ek, const msg = try convertExecutionError(err);
        @"error" = e;
        error_kind = ek;
        try sig.runtime.stable_log.programFailure(tc, instr_info.program_meta.pubkey, msg);
    }

    const effects = try utils.createSyscallEffect(allocator, .{
        .tc = tc,
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

pub fn convertExecutionError(err: sig.vm.ExecutionError) !struct { u8, pb.ErrKind, []const u8 } {
    return switch (err) {
        EbpfError.ElfError => .{ 1, .EBPF, "ELF error" },
        EbpfError.FunctionAlreadyRegistered => .{ 2, .EBPF, "function was already registered" },
        EbpfError.CallDepthExceeded => .{ 3, .EBPF, "exceeded max BPF to BPF call depth" },
        EbpfError.ExitRootCallFrame => .{ 4, .EBPF, "attempted to exit root call frame" },
        EbpfError.DivisionByZero => .{ 5, .EBPF, "divide by zero at BPF instruction" },
        EbpfError.DivideOverflow => .{ 6, .EBPF, "division overflow at BPF instruction" },
        EbpfError.ExecutionOverrun => .{ 7, .EBPF, "attempted to execute past the end of the text segment at BPF instruction" },
        EbpfError.CallOutsideTextSegment => .{ 8, .EBPF, "callx attempted to call outside of the text segment" },
        EbpfError.ExceededMaxInstructions => .{ 9, .EBPF, "exceeded CUs meter at BPF instruction" },
        EbpfError.JitNotCompiled => .{ 10, .EBPF, "program has not been JIT-compiled" },
        EbpfError.InvalidVirtualAddress => .{ 11, .EBPF, "invalid virtual address" },
        EbpfError.InvalidMemoryRegion => .{ 12, .EBPF, "Invalid memory region at index" },
        EbpfError.AccessViolation => .{ 13, .EBPF, "Access violation" },
        EbpfError.StackAccessViolation => .{ 13, .EBPF, "Access violation" },
        EbpfError.InvalidInstruction => .{ 15, .EBPF, "invalid BPF instruction" },
        EbpfError.UnsupportedInstruction => .{ 16, .EBPF, "unsupported BPF instruction" },
        EbpfError.ExhaustedTextSegment => .{ 17, .EBPF, "Compilation exhausted text segment at BPF instruction" },
        EbpfError.LibcInvocationFailed => .{ 18, .EBPF, "Libc calling returned error code" },
        EbpfError.VerifierError => .{ 19, .EBPF, "Verifier error" },
        EbpfError.SyscallError => return error.EbpfSyscallError,

        SyscallError.InvalidString => .{ 1, .SYSCALL, "invalid utf-8 sequence" },
        SyscallError.Abort => .{ 2, .SYSCALL, "SBF program panicked" },
        SyscallError.Panic => .{ 3, .SYSCALL, "SBF program Panicked in..." },
        SyscallError.InvokeContextBorrowFailed => .{ 4, .SYSCALL, "Cannot borrow invoke context" },
        SyscallError.MalformedSignerSeed => .{ 5, .SYSCALL, "Malformed signer seed" },
        SyscallError.BadSeeds => .{ 6, .SYSCALL, "Could not create program address with signer seeds" },
        SyscallError.ProgramNotSupported => .{ 7, .SYSCALL, "Program not supported by inner instructions" },
        SyscallError.UnalignedPointer => .{ 8, .SYSCALL, "Unaligned pointer" },
        SyscallError.TooManySigners => .{ 9, .SYSCALL, "Too many signers" },
        SyscallError.InstructionTooLarge => .{ 10, .SYSCALL, "Instruction passed to inner instruction is too large" },
        SyscallError.TooManyAccounts => .{ 11, .SYSCALL, "Too many accounts passed to inner instruction" },
        SyscallError.CopyOverlapping => .{ 12, .SYSCALL, "Overlapping copy" },
        SyscallError.ReturnDataTooLarge => .{ 13, .SYSCALL, "Return data too large" },
        SyscallError.TooManySlices => .{ 14, .SYSCALL, "Hashing too many sequences" },
        SyscallError.InvalidLength => .{ 15, .SYSCALL, "InvalidLength" },
        SyscallError.MaxInstructionDataLenExceeded => .{ 16, .SYSCALL, "Invoked an instruction with data that is too large" },
        SyscallError.MaxInstructionAccountsExceeded => .{ 17, .SYSCALL, "Invoked an instruction with too many accounts" },
        SyscallError.MaxInstructionAccountInfosExceeded => .{ 18, .SYSCALL, "Invoked an instruction with too many account info's" },
        SyscallError.InvalidAttribute => .{ 19, .SYSCALL, "InvalidAttribute" },
        SyscallError.InvalidPointer => .{ 20, .SYSCALL, "Invalid pointer" },
        SyscallError.ArithmeticOverflow => .{ 21, .SYSCALL, "Arithmetic overflow" },

        InstructionError.GenericError => .{ 1, .INSTRUCTION, "generic instruction error" },
        InstructionError.InvalidArgument => .{ 2, .INSTRUCTION, "invalid program argument" },
        InstructionError.InvalidInstructionData => .{ 3, .INSTRUCTION, "invalid instruction data" },
        InstructionError.InvalidAccountData => .{ 4, .INSTRUCTION, "invalid account data for instruction" },
        InstructionError.AccountDataTooSmall => .{ 5, .INSTRUCTION, "account data too small for instruction" },
        InstructionError.InsufficientFunds => .{ 6, .INSTRUCTION, "insufficient funds for instruction" },
        InstructionError.IncorrectProgramId => .{ 7, .INSTRUCTION, "incorrect program id for instruction" },
        InstructionError.MissingRequiredSignature => .{ 8, .INSTRUCTION, "missing required signature for instruction" },
        InstructionError.AccountAlreadyInitialized => .{ 9, .INSTRUCTION, "instruction requires an uninitialized account" },
        InstructionError.UninitializedAccount => .{ 10, .INSTRUCTION, "instruction requires an initialized account" },
        InstructionError.UnbalancedInstruction => .{ 11, .INSTRUCTION, "sum of account balances before and after instruction do not match" },
        InstructionError.ModifiedProgramId => .{ 12, .INSTRUCTION, "instruction illegally modified the program id of an account" },
        InstructionError.ExternalAccountLamportSpend => .{ 13, .INSTRUCTION, "instruction spent from the balance of an account it does not own" },
        InstructionError.ExternalAccountDataModified => .{ 14, .INSTRUCTION, "instruction modified data of an account it does not own" },
        InstructionError.ReadonlyLamportChange => .{ 15, .INSTRUCTION, "instruction changed the balance of a read-only account" },
        InstructionError.ReadonlyDataModified => .{ 16, .INSTRUCTION, "instruction modified data of a read-only account" },
        InstructionError.DuplicateAccountIndex => .{ 17, .INSTRUCTION, "instruction contains duplicate accounts" },
        InstructionError.ExecutableModified => .{ 18, .INSTRUCTION, "instruction changed executable bit of an account" },
        InstructionError.RentEpochModified => .{ 19, .INSTRUCTION, "instruction modified rent epoch of an account" },
        InstructionError.NotEnoughAccountKeys => .{ 20, .INSTRUCTION, "insufficient account keys for instruction" },
        InstructionError.AccountDataSizeChanged => .{ 21, .INSTRUCTION, "program other than the account's owner changed the size of the account data" },
        InstructionError.AccountNotExecutable => .{ 22, .INSTRUCTION, "instruction expected an executable account" },
        InstructionError.AccountBorrowFailed => .{ 23, .INSTRUCTION, "instruction tries to borrow reference for an account which is already borrowed" },
        InstructionError.AccountBorrowOutstanding => .{ 24, .INSTRUCTION, "instruction left account with an outstanding borrowed reference" },
        InstructionError.DuplicateAccountOutOfSync => .{ 25, .INSTRUCTION, "instruction modifications of multiply-passed account differ" },
        InstructionError.Custom => .{ 26, .INSTRUCTION, "custom program error" },
        InstructionError.InvalidError => .{ 27, .INSTRUCTION, "program returned invalid error code" },
        InstructionError.ExecutableDataModified => .{ 28, .INSTRUCTION, "instruction changed executable accounts data" },
        InstructionError.ExecutableLamportChange => .{ 29, .INSTRUCTION, "instruction changed the balance of an executable account" },
        InstructionError.ExecutableAccountNotRentExempt => .{ 30, .INSTRUCTION, "executable accounts must be rent exempt" },
        InstructionError.UnsupportedProgramId => .{ 31, .INSTRUCTION, "Unsupported program id" },
        InstructionError.CallDepth => .{ 32, .INSTRUCTION, "Cross-program invocation call depth too deep" },
        InstructionError.MissingAccount => .{ 33, .INSTRUCTION, "An account required by the instruction is missing" },
        InstructionError.ReentrancyNotAllowed => .{ 34, .INSTRUCTION, "Cross-program invocation reentrancy not allowed for this instruction" },
        InstructionError.MaxSeedLengthExceeded => .{ 35, .INSTRUCTION, "Length of the seed is too long for address generation" },
        InstructionError.InvalidSeeds => .{ 36, .INSTRUCTION, "Provided seeds do not result in a valid address" },
        InstructionError.InvalidRealloc => .{ 37, .INSTRUCTION, "Failed to reallocate account data" },
        InstructionError.ComputationalBudgetExceeded => .{ 38, .INSTRUCTION, "Computational budget exceeded" },
        InstructionError.PrivilegeEscalation => .{ 39, .INSTRUCTION, "Cross-program invocation with unauthorized signer or writable account" },
        InstructionError.ProgramEnvironmentSetupFailure => .{ 40, .INSTRUCTION, "Failed to create program execution environment" },
        InstructionError.ProgramFailedToComplete => .{ 41, .INSTRUCTION, "Program failed to complete" },
        InstructionError.ProgramFailedToCompile => .{ 42, .INSTRUCTION, "Program failed to compile" },
        InstructionError.Immutable => .{ 43, .INSTRUCTION, "Account is immutable" },
        InstructionError.IncorrectAuthority => .{ 44, .INSTRUCTION, "Incorrect authority provided" },
        InstructionError.BorshIoError => .{ 45, .INSTRUCTION, "Failed to serialize or deserialize account data" },
        InstructionError.AccountNotRentExempt => .{ 46, .INSTRUCTION, "An account does not have enough lamports to be rent-exempt" },
        InstructionError.InvalidAccountOwner => .{ 47, .INSTRUCTION, "Invalid account owner" },
        InstructionError.ProgramArithmeticOverflow => .{ 48, .INSTRUCTION, "Program arithmetic overflowed" },
        InstructionError.UnsupportedSysvar => .{ 49, .INSTRUCTION, "Unsupported sysvar" },
        InstructionError.IllegalOwner => .{ 50, .INSTRUCTION, "Provided owner is not allowed" },
        InstructionError.MaxAccountsDataAllocationsExceeded => .{ 51, .INSTRUCTION, "Accounts data allocations exceeded the maximum allowed per transaction" },
        InstructionError.MaxAccountsExceeded => .{ 52, .INSTRUCTION, "Max accounts exceeded" },
        InstructionError.MaxInstructionTraceLengthExceeded => .{ 53, .INSTRUCTION, "Max instruction trace length exceeded" },
        InstructionError.BuiltinProgramsMustConsumeComputeUnits => .{ 54, .INSTRUCTION, "Builtin programs must consume compute units" },

        else => {
            std.debug.print("Sig error: {s}\n", .{@errorName(err)});
            return error.SigError;
        },
    };
}
