const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");

const ManagedString = @import("protobuf").ManagedString;

const features = sig.runtime.features;
const executor = sig.runtime.executor;
const sysvar = sig.runtime.sysvar;

const EbpfError = sig.vm.EbpfError;
const SyscallError = sig.vm.SyscallError;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionInfo = sig.runtime.instruction_info.InstructionInfo;
const EpochContext = sig.runtime.transaction_context.EpochContext;
const SlotContext = sig.runtime.transaction_context.SlotContext;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;
const TransactionContextAccount = sig.runtime.transaction_context.TransactionContextAccount;

const Pubkey = sig.core.Pubkey;

const intFromInstructionError = sig.core.instruction.intFromInstructionError;

const EMIT_LOGS = false;

pub fn createExecutionContexts(allocator: std.mem.Allocator, instr_ctx: pb.InstrContext, emit_logs: bool) !struct {
    *EpochContext,
    *SlotContext,
    *TransactionContext,
} {
    const ec = try allocator.create(EpochContext);
    ec.* = .{
        .allocator = allocator,
        .feature_set = try createFeatureSet(allocator, instr_ctx),
    };

    const sc = try allocator.create(SlotContext);
    sc.* = .{
        .allocator = allocator,
        .ec = ec,
        .sysvar_cache = try createSysvarCache(allocator, instr_ctx),
    };

    const tc = try allocator.create(TransactionContext);
    tc.* = .{
        .allocator = allocator,
        .ec = ec,
        .sc = sc,
        .accounts = try createTransactionContextAccounts(
            allocator,
            instr_ctx.accounts.items,
        ),
        .serialized_accounts = .{},
        .instruction_stack = .{},
        .instruction_trace = .{},
        .return_data = .{},
        .accounts_resize_delta = 0,
        .compute_meter = instr_ctx.cu_avail,
        .compute_budget = sig.runtime.ComputeBudget.default(instr_ctx.cu_avail),
        .custom_error = null,
        .log_collector = if (emit_logs) sig.runtime.LogCollector.init(null) else null,
        .prev_blockhash = sig.core.Hash.ZEROES,
        .prev_lamports_per_signature = 0,
    };

    if (sc.sysvar_cache.get(sysvar.RecentBlockhashes) catch null) |recent_blockhashes| {
        if (recent_blockhashes.entries.len > 0) {
            const prev_entry = recent_blockhashes.entries[recent_blockhashes.entries.len - 1];
            tc.prev_blockhash = prev_entry.blockhash;
            tc.prev_lamports_per_signature = prev_entry.fee_calculator.lamports_per_signature;
        }
    }

    return .{ ec, sc, tc };
}

pub fn createFeatureSet(
    allocator: std.mem.Allocator,
    pb_ctx: pb.InstrContext,
) !features.FeatureSet {
    errdefer |err| {
        std.debug.print("createFeatureSet: error={}\n", .{err});
    }

    const pb_epoch_context = pb_ctx.epoch_context orelse return features.FeatureSet.EMPTY;
    const pb_feature_set = pb_epoch_context.features orelse return features.FeatureSet.EMPTY;

    var indexed_features = std.AutoArrayHashMap(u64, Pubkey).init(allocator);
    defer indexed_features.deinit();

    for (features.FEATURES) |feature| {
        try indexed_features.put(@bitCast(feature.data[0..8].*), feature);
    }

    var feature_set = features.FeatureSet.EMPTY;
    for (pb_feature_set.features.items) |id| {
        if (indexed_features.get(id)) |pubkey| {
            try feature_set.active.put(allocator, pubkey, 0);
        }
    }

    return feature_set;
}

pub fn createTransactionContextAccounts(
    allocator: std.mem.Allocator,
    pb_accounts: []const pb.AcctState,
) ![]TransactionContextAccount {
    errdefer |err| {
        std.debug.print("createTransactionContextAccounts: error={}\n", .{err});
    }

    var accounts = std.ArrayList(TransactionContextAccount).init(allocator);
    errdefer {
        for (accounts.items) |account| account.deinit(allocator);
        accounts.deinit();
    }

    for (pb_accounts) |pb_account| {
        const account_data = try allocator.dupe(u8, pb_account.data.getSlice());
        errdefer allocator.free(account_data);

        if (pb_account.owner.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
        try accounts.append(
            TransactionContextAccount.init(
                .{ .data = pb_account.address.getSlice()[0..Pubkey.SIZE].* },
                .{
                    .lamports = pb_account.lamports,
                    .data = account_data,
                    .owner = .{ .data = pb_account.owner.getSlice()[0..Pubkey.SIZE].* },
                    .executable = pb_account.executable,
                    .rent_epoch = pb_account.rent_epoch,
                },
            ),
        );
    }

    return accounts.toOwnedSlice();
}

pub fn createInstructionInfo(
    allocator: std.mem.Allocator,
    tc: *const TransactionContext,
    program_id: Pubkey,
    instruction: []const u8,
    pb_instruction_accounts: []const pb.InstrAcct,
) !InstructionInfo {
    errdefer |err| {
        std.debug.print("createInstructionInfo: error={}\n", .{err});
    }

    const program_index_in_transaction = blk: {
        for (tc.accounts, 0..) |acc, i| {
            if (acc.pubkey.equals(&program_id)) {
                break :blk i;
            }
        }
        return error.CouldNotFindProgram;
    };

    var account_metas = std.BoundedArray(
        InstructionInfo.AccountMeta,
        InstructionInfo.MAX_ACCOUNT_METAS,
    ){};

    for (pb_instruction_accounts, 0..) |acc, idx| {
        if (acc.index >= tc.accounts.len)
            return error.AccountIndexOutOfBounds;

        const index_in_callee = blk: {
            for (0..idx) |i| {
                if (acc.index ==
                    pb_instruction_accounts[i].index)
                {
                    break :blk i;
                }
            }
            break :blk idx;
        };

        try account_metas.append(.{
            .pubkey = tc.accounts[acc.index].pubkey,
            .index_in_transaction = @intCast(acc.index),
            .index_in_caller = @intCast(acc.index),
            .index_in_callee = @intCast(index_in_callee),
            .is_signer = acc.is_signer,
            .is_writable = acc.is_writable,
        });
    }

    return .{
        .program_meta = .{
            .pubkey = program_id,
            .index_in_transaction = @intCast(program_index_in_transaction),
        },
        .account_metas = account_metas,
        .instruction_data = try allocator.dupe(u8, instruction),
        .initial_account_lamports = 0,
    };
}

pub fn createSysvarCache(
    allocator: std.mem.Allocator,
    ctx: pb.InstrContext,
) !sig.runtime.SysvarCache {
    errdefer |err| {
        std.debug.print("createSysvarCache: error={}\n", .{err});
    }

    var sysvar_cache = sig.runtime.SysvarCache{};
    sysvar_cache.clock = try cloneSysvarData(allocator, ctx, sysvar.Clock.ID);
    if (sysvar_cache.clock == null) {
        var clock = sysvar.Clock.DEFAULT;
        clock.slot = 10;
        sysvar_cache.clock = try sig.bincode.writeAlloc(
            allocator,
            clock,
            .{},
        );
    }
    sysvar_cache.epoch_schedule = try cloneSysvarData(allocator, ctx, sig.core.EpochSchedule.ID);
    if (sysvar_cache.epoch_schedule == null) {
        sysvar_cache.epoch_schedule = try sig.bincode.writeAlloc(
            allocator,
            sig.core.EpochSchedule.DEFAULT,
            .{},
        );
    }
    sysvar_cache.epoch_rewards = try cloneSysvarData(allocator, ctx, sysvar.EpochRewards.ID);
    sysvar_cache.rent = try cloneSysvarData(allocator, ctx, sysvar.Rent.ID);
    if (sysvar_cache.rent == null) {
        sysvar_cache.rent = sig.bincode.writeAlloc(
            allocator,
            sysvar.Rent.DEFAULT,
            .{},
        ) catch null;
    }
    sysvar_cache.last_restart_slot = try cloneSysvarData(allocator, ctx, sysvar.LastRestartSlot.ID);
    if (sysvar_cache.last_restart_slot == null) {
        sysvar_cache.last_restart_slot = sig.bincode.writeAlloc(
            allocator,
            sysvar.LastRestartSlot{
                .last_restart_slot = 5000,
            },
            .{},
        ) catch null;
    }
    if (sysvar_cache.slot_hashes == null) {
        if (try cloneSysvarData(allocator, ctx, sysvar.SlotHashes.ID)) |slot_hashes_data| {
            sysvar_cache.slot_hashes_obj = sig.bincode.readFromSlice(
                allocator,
                sysvar.SlotHashes,
                slot_hashes_data,
                .{},
            ) catch null;
            if (sysvar_cache.slot_hashes_obj != null) {
                sysvar_cache.slot_hashes = slot_hashes_data;
            }
        }
    }
    if (sysvar_cache.stake_history == null) {
        if (try cloneSysvarData(allocator, ctx, sysvar.StakeHistory.ID)) |stake_history_data| {
            sysvar_cache.stake_history_obj = sig.bincode.readFromSlice(
                allocator,
                sysvar.StakeHistory,
                stake_history_data,
                .{},
            ) catch null;
            if (sysvar_cache.stake_history_obj != null) {
                sysvar_cache.stake_history = stake_history_data;
            }
        }
    }
    if (sysvar_cache.fees == null) {
        if (try cloneSysvarData(allocator, ctx, sysvar.Fees.ID)) |fees_data| {
            sysvar_cache.fees = sig.bincode.readFromSlice(
                allocator,
                sysvar.Fees,
                fees_data,
                .{},
            ) catch null;
        }
    }
    if (sysvar_cache.recent_blockhashes == null) {
        if (try cloneSysvarData(allocator, ctx, sysvar.RecentBlockhashes.ID)) |recent_blockhashes_data| {
            sysvar_cache.recent_blockhashes = sig.bincode.readFromSlice(
                allocator,
                sysvar.RecentBlockhashes,
                recent_blockhashes_data,
                .{},
            ) catch null;
        }
    }
    return sysvar_cache;
}

fn cloneSysvarData(allocator: std.mem.Allocator, ctx: pb.InstrContext, pubkey: Pubkey) !?[]const u8 {
    for (ctx.accounts.items) |acc| {
        if (acc.lamports > 0 and std.mem.eql(u8, acc.address.getSlice(), &pubkey.data)) {
            return try allocator.dupe(u8, acc.data.getSlice());
        }
    }
    return null;
}

pub fn createInstrEffects(
    allocator: std.mem.Allocator,
    tc: *const TransactionContext,
    result: ?InstructionError,
) !pb.InstrEffects {
    return pb.InstrEffects{
        .result = intFromResult(result),
        .custom_err = tc.custom_error orelse 0,
        .modified_accounts = try modifiedAccounts(allocator, tc),
        .cu_avail = tc.compute_meter,
        .return_data = try ManagedString.copy(
            tc.return_data.data.constSlice(),
            allocator,
        ),
    };
}

fn intFromResult(result: ?InstructionError) i32 {
    return if (result) |err|
        intFromInstructionError(err)
    else
        0;
}

fn modifiedAccounts(allocator: std.mem.Allocator, tc: *const TransactionContext) !std.ArrayList(pb.AcctState) {
    var accounts = std.ArrayList(pb.AcctState).init(allocator);
    errdefer accounts.deinit();

    for (tc.accounts) |acc| {
        try accounts.append(.{
            .address = try ManagedString.copy(
                &acc.pubkey.data,
                allocator,
            ),
            .lamports = acc.account.lamports,
            .data = try ManagedString.copy(
                acc.account.data,
                allocator,
            ),
            .executable = acc.account.executable,
            .rent_epoch = acc.account.rent_epoch,
            .owner = try ManagedString.copy(
                &acc.account.owner.data,
                allocator,
            ),
        });
    }

    return accounts;
}

pub fn printPbInstrContext(ctx: pb.InstrContext) !void {
    var buffer = [_]u8{0} ** (1024 * 1024);
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    writer.writeAll("InstrContext {") catch return;
    std.fmt.format(writer, "\n\tprogram_id: {any}", .{ctx.program_id.getSlice()}) catch return;
    writer.writeAll(",\n\taccounts: [") catch return;
    for (ctx.accounts.items) |acc| {
        writer.writeAll("\n\t\tAcctState {") catch return;
        std.fmt.format(writer, "\n\t\t\taddress: {any}", .{acc.address.getSlice()}) catch return;
        std.fmt.format(writer, ",\n\t\t\tlamports: {d}", .{acc.lamports}) catch return;
        std.fmt.format(writer, ",\n\t\t\tdata: {any}", .{acc.data.getSlice()}) catch return;
        std.fmt.format(writer, ",\n\t\t\texecutable: {}", .{acc.executable}) catch return;
        std.fmt.format(writer, ",\n\t\t\trent_epoch: {}", .{acc.rent_epoch}) catch return;
        std.fmt.format(writer, ",\n\t\t\towner: {any}", .{acc.owner.getSlice()}) catch return;
        writer.writeAll("\n\t\t},\n") catch return;
    }
    writer.writeAll("\t],\n\tinstr_accounts: [") catch return;
    for (ctx.instr_accounts.items) |acc| {
        writer.writeAll("\n\t\tInstrAcct {") catch return;
        std.fmt.format(writer, "\n\t\t\tindex: {}", .{acc.index}) catch return;
        std.fmt.format(writer, ",\n\t\t\tis_signer: {}", .{acc.is_signer}) catch return;
        std.fmt.format(writer, ",\n\t\t\tis_writable: {}", .{acc.is_writable}) catch return;
        writer.writeAll("\n\t\t},\n") catch return;
    }
    std.fmt.format(writer, "\t],\n\tdata: {any}", .{ctx.data.getSlice()}) catch return;
    std.fmt.format(writer, ",\n\tcu_avail: {d}", .{ctx.cu_avail}) catch return;
    writer.writeAll(",\n}\n") catch return;
    std.debug.print("{s}", .{writer.context.getWritten()});
}

pub fn printPbInstrEffects(effects: pb.InstrEffects) !void {
    var buffer = [_]u8{0} ** (1024 * 1024);
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    writer.writeAll("InstrEffects {") catch return;
    std.fmt.format(writer, "\n\tresult: {d}", .{effects.result}) catch return;
    std.fmt.format(writer, ",\n\tcustom_err: {d}", .{effects.custom_err}) catch return;
    writer.writeAll(",\n\tmodified_accounts: [") catch return;
    for (effects.modified_accounts.items) |acc| {
        writer.writeAll("\n\t\tAcctState {") catch return;
        std.fmt.format(writer, "\n\t\t\taddress: {any}", .{acc.address.getSlice()}) catch return;
        std.fmt.format(writer, ",\n\t\t\tlamports: {d}", .{acc.lamports}) catch return;
        std.fmt.format(writer, ",\n\t\t\tdata: {any}", .{acc.data.getSlice()}) catch return;
        std.fmt.format(writer, ",\n\t\t\texecutable: {}", .{acc.executable}) catch return;
        std.fmt.format(writer, ",\n\t\t\trent_epoch: {}", .{acc.rent_epoch}) catch return;
        std.fmt.format(writer, ",\n\t\t\towner: {any}", .{acc.owner.getSlice()}) catch return;
        writer.writeAll("\n\t\t},\n") catch return;
    }
    writer.writeAll("\t],") catch return;
    std.fmt.format(writer, ",\n\tcu_avail: {d}", .{effects.cu_avail}) catch return;
    std.fmt.format(writer, ",\n\treturn_data: {any}", .{effects.return_data.getSlice()}) catch return;
    writer.writeAll("\n}\n") catch return;
    std.debug.print("{s}", .{writer.context.getWritten()});
}

pub fn createSyscallEffect(allocator: std.mem.Allocator, params: struct {
    tc: *const TransactionContext,
    err: i64,
    err_kind: pb.ErrKind,
    heap: []const u8,
    stack: []const u8,
    rodata: []const u8,
    frame_count: u64,
    memory_map: sig.vm.memory.MemoryMap,
    registers: sig.vm.interpreter.RegisterMap = sig.vm.interpreter.RegisterMap.initFill(0),
}) !pb.SyscallEffects {
    var log = std.ArrayList(u8).init(allocator);
    defer log.deinit();
    if (params.tc.log_collector) |log_collector| {
        for (log_collector.collect()) |msg| {
            try log.appendSlice(msg);
            try log.append('\n');
        }
        if (log.items.len > 0) _ = log.pop();
    }

    const input_data_regions = try extractInputDataRegions(
        allocator,
        params.memory_map,
    );

    return .{
        .@"error" = params.err,
        .error_kind = params.err_kind,
        .cu_avail = params.tc.compute_meter,
        .heap = try ManagedString.copy(params.heap, allocator),
        .stack = try ManagedString.copy(params.stack, allocator),
        .inputdata = .Empty, // Deprecated
        .input_data_regions = input_data_regions,
        .frame_count = params.frame_count,
        .log = try ManagedString.copy(log.items, allocator),
        .rodata = try ManagedString.copy(params.rodata, allocator),
        .r0 = params.registers.get(.r0),
        .r1 = params.registers.get(.r1),
        .r2 = params.registers.get(.r2),
        .r3 = params.registers.get(.r3),
        .r4 = params.registers.get(.r4),
        .r5 = params.registers.get(.r5),
        .r6 = params.registers.get(.r6),
        .r7 = params.registers.get(.r7),
        .r8 = params.registers.get(.r8),
        .r9 = params.registers.get(.r9),
        .r10 = params.registers.get(.r10),
        .pc = params.registers.get(.pc),
    };
}

pub fn extractInputDataRegions(
    allocator: std.mem.Allocator,
    memory_map: sig.vm.memory.MemoryMap,
) !std.ArrayList(pb.InputDataRegion) {
    var regions = std.ArrayList(pb.InputDataRegion).init(allocator);
    errdefer regions.deinit();

    const mm_regions: []const sig.vm.memory.Region = switch (memory_map) {
        .aligned => |amm| amm.regions,
        .unaligned => |umm| umm.regions,
    };

    for (mm_regions) |region| {
        if (region.vm_addr_start >= sig.vm.memory.INPUT_START) {
            try regions.append(.{
                .offset = region.vm_addr_start - sig.vm.memory.INPUT_START,
                .is_writable = region.host_memory == .mutable,
                .content = try ManagedString.copy(region.constSlice(), allocator),
            });
        }
    }

    std.mem.sort(pb.InputDataRegion, regions.items, {}, struct {
        pub fn cmp(_: void, a: pb.InputDataRegion, b: pb.InputDataRegion) bool {
            return a.offset < b.offset;
        }
    }.cmp);

    return regions;
}

pub fn convertExecutionError(err: sig.vm.ExecutionError) !struct { u8, pb.ErrKind, []const u8 } {
    return switch (err) {
        // zig fmt: off
        EbpfError.ElfError                  => .{ 1, .EBPF, "ELF error" },
        EbpfError.FunctionAlreadyRegistered => .{ 2, .EBPF, "function was already registered" },
        EbpfError.CallDepthExceeded         => .{ 3, .EBPF, "exceeded max BPF to BPF call depth" },
        EbpfError.ExitRootCallFrame         => .{ 4, .EBPF, "attempted to exit root call frame" },
        EbpfError.DivisionByZero            => .{ 5, .EBPF, "divide by zero at BPF instruction" },
        EbpfError.DivideOverflow            => .{ 6, .EBPF, "division overflow at BPF instruction" },
        EbpfError.ExecutionOverrun          => .{ 7, .EBPF, "attempted to execute past the end of the text segment at BPF instruction" },
        EbpfError.CallOutsideTextSegment    => .{ 8, .EBPF, "callx attempted to call outside of the text segment" },
        EbpfError.ExceededMaxInstructions   => .{ 9, .EBPF, "exceeded CUs meter at BPF instruction" },
        EbpfError.JitNotCompiled            => .{ 10, .EBPF, "program has not been JIT-compiled" },
        EbpfError.InvalidVirtualAddress     => .{ 11, .EBPF, "invalid virtual address" },
        EbpfError.InvalidMemoryRegion       => .{ 12, .EBPF, "Invalid memory region at index" },
        EbpfError.AccessViolation           => .{ 13, .EBPF, "Access violation" },
        EbpfError.StackAccessViolation      => .{ 13, .EBPF, "Access violation" },
        EbpfError.InvalidInstruction        => .{ 15, .EBPF, "invalid BPF instruction" },
        EbpfError.UnsupportedInstruction    => .{ 16, .EBPF, "unsupported BPF instruction" },
        EbpfError.ExhaustedTextSegment      => .{ 17, .EBPF, "Compilation exhausted text segment at BPF instruction" },
        EbpfError.LibcInvocationFailed      => .{ 18, .EBPF, "Libc calling returned error code" },
        EbpfError.VerifierError             => .{ 19, .EBPF, "Verifier error" },
        EbpfError.SyscallError              => return error.EbpfSyscallError,

        SyscallError.InvalidString                      => .{ 1, .SYSCALL, "invalid utf-8 sequence" },
        SyscallError.Abort                              => .{ 2, .SYSCALL, "SBF program panicked" },
        SyscallError.Panic                              => .{ 3, .SYSCALL, "SBF program Panicked in..." },
        SyscallError.InvokeContextBorrowFailed          => .{ 4, .SYSCALL, "Cannot borrow invoke context" },
        SyscallError.MalformedSignerSeed                => .{ 5, .SYSCALL, "Malformed signer seed" },
        SyscallError.BadSeeds                           => .{ 6, .SYSCALL, "Could not create program address with signer seeds" },
        SyscallError.ProgramNotSupported                => .{ 7, .SYSCALL, "Program not supported by inner instructions" },
        SyscallError.UnalignedPointer                   => .{ 8, .SYSCALL, "Unaligned pointer" },
        SyscallError.TooManySigners                     => .{ 9, .SYSCALL, "Too many signers" },
        SyscallError.InstructionTooLarge                => .{ 10, .SYSCALL, "Instruction passed to inner instruction is too large" },
        SyscallError.TooManyAccounts                    => .{ 11, .SYSCALL, "Too many accounts passed to inner instruction" },
        SyscallError.CopyOverlapping                    => .{ 12, .SYSCALL, "Overlapping copy" },
        SyscallError.ReturnDataTooLarge                 => .{ 13, .SYSCALL, "Return data too large" },
        SyscallError.TooManySlices                      => .{ 14, .SYSCALL, "Hashing too many sequences" },
        SyscallError.InvalidLength                      => .{ 15, .SYSCALL, "InvalidLength" },
        SyscallError.MaxInstructionDataLenExceeded      => .{ 16, .SYSCALL, "Invoked an instruction with data that is too large" },
        SyscallError.MaxInstructionAccountsExceeded     => .{ 17, .SYSCALL, "Invoked an instruction with too many accounts" },
        SyscallError.MaxInstructionAccountInfosExceeded => .{ 18, .SYSCALL, "Invoked an instruction with too many account info's" },
        SyscallError.InvalidAttribute                   => .{ 19, .SYSCALL, "InvalidAttribute" },
        SyscallError.InvalidPointer                     => .{ 20, .SYSCALL, "Invalid pointer" },
        SyscallError.ArithmeticOverflow                 => .{ 21, .SYSCALL, "Arithmetic overflow" },

        InstructionError.GenericError                           => .{ 1, .INSTRUCTION, "generic instruction error" },
        InstructionError.InvalidArgument                        => .{ 2, .INSTRUCTION, "invalid program argument" },
        InstructionError.InvalidInstructionData                 => .{ 3, .INSTRUCTION, "invalid instruction data" },
        InstructionError.InvalidAccountData                     => .{ 4, .INSTRUCTION, "invalid account data for instruction" },
        InstructionError.AccountDataTooSmall                    => .{ 5, .INSTRUCTION, "account data too small for instruction" },
        InstructionError.InsufficientFunds                      => .{ 6, .INSTRUCTION, "insufficient funds for instruction" },
        InstructionError.IncorrectProgramId                     => .{ 7, .INSTRUCTION, "incorrect program id for instruction" },
        InstructionError.MissingRequiredSignature               => .{ 8, .INSTRUCTION, "missing required signature for instruction" },
        InstructionError.AccountAlreadyInitialized              => .{ 9, .INSTRUCTION, "instruction requires an uninitialized account" },
        InstructionError.UninitializedAccount                   => .{ 10, .INSTRUCTION, "instruction requires an initialized account" },
        InstructionError.UnbalancedInstruction                  => .{ 11, .INSTRUCTION, "sum of account balances before and after instruction do not match" },
        InstructionError.ModifiedProgramId                      => .{ 12, .INSTRUCTION, "instruction illegally modified the program id of an account" },
        InstructionError.ExternalAccountLamportSpend            => .{ 13, .INSTRUCTION, "instruction spent from the balance of an account it does not own" },
        InstructionError.ExternalAccountDataModified            => .{ 14, .INSTRUCTION, "instruction modified data of an account it does not own" },
        InstructionError.ReadonlyLamportChange                  => .{ 15, .INSTRUCTION, "instruction changed the balance of a read-only account" },
        InstructionError.ReadonlyDataModified                   => .{ 16, .INSTRUCTION, "instruction modified data of a read-only account" },
        InstructionError.DuplicateAccountIndex                  => .{ 17, .INSTRUCTION, "instruction contains duplicate accounts" },
        InstructionError.ExecutableModified                     => .{ 18, .INSTRUCTION, "instruction changed executable bit of an account" },
        InstructionError.RentEpochModified                      => .{ 19, .INSTRUCTION, "instruction modified rent epoch of an account" },
        InstructionError.NotEnoughAccountKeys                   => .{ 20, .INSTRUCTION, "insufficient account keys for instruction" },
        InstructionError.AccountDataSizeChanged                 => .{ 21, .INSTRUCTION, "program other than the account's owner changed the size of the account data" },
        InstructionError.AccountNotExecutable                   => .{ 22, .INSTRUCTION, "instruction expected an executable account" },
        InstructionError.AccountBorrowFailed                    => .{ 23, .INSTRUCTION, "instruction tries to borrow reference for an account which is already borrowed" },
        InstructionError.AccountBorrowOutstanding               => .{ 24, .INSTRUCTION, "instruction left account with an outstanding borrowed reference" },
        InstructionError.DuplicateAccountOutOfSync              => .{ 25, .INSTRUCTION, "instruction modifications of multiply-passed account differ" },
        InstructionError.Custom                                 => .{ 26, .INSTRUCTION, "custom program error" },
        InstructionError.InvalidError                           => .{ 27, .INSTRUCTION, "program returned invalid error code" },
        InstructionError.ExecutableDataModified                 => .{ 28, .INSTRUCTION, "instruction changed executable accounts data" },
        InstructionError.ExecutableLamportChange                => .{ 29, .INSTRUCTION, "instruction changed the balance of an executable account" },
        InstructionError.ExecutableAccountNotRentExempt         => .{ 30, .INSTRUCTION, "executable accounts must be rent exempt" },
        InstructionError.UnsupportedProgramId                   => .{ 31, .INSTRUCTION, "Unsupported program id" },
        InstructionError.CallDepth                              => .{ 32, .INSTRUCTION, "Cross-program invocation call depth too deep" },
        InstructionError.MissingAccount                         => .{ 33, .INSTRUCTION, "An account required by the instruction is missing" },
        InstructionError.ReentrancyNotAllowed                   => .{ 34, .INSTRUCTION, "Cross-program invocation reentrancy not allowed for this instruction" },
        InstructionError.MaxSeedLengthExceeded                  => .{ 35, .INSTRUCTION, "Length of the seed is too long for address generation" },
        InstructionError.InvalidSeeds                           => .{ 36, .INSTRUCTION, "Provided seeds do not result in a valid address" },
        InstructionError.InvalidRealloc                         => .{ 37, .INSTRUCTION, "Failed to reallocate account data" },
        InstructionError.ComputationalBudgetExceeded            => .{ 38, .INSTRUCTION, "Computational budget exceeded" },
        InstructionError.PrivilegeEscalation                    => .{ 39, .INSTRUCTION, "Cross-program invocation with unauthorized signer or writable account" },
        InstructionError.ProgramEnvironmentSetupFailure         => .{ 40, .INSTRUCTION, "Failed to create program execution environment" },
        InstructionError.ProgramFailedToComplete                => .{ 41, .INSTRUCTION, "Program failed to complete" },
        InstructionError.ProgramFailedToCompile                 => .{ 42, .INSTRUCTION, "Program failed to compile" },
        InstructionError.Immutable                              => .{ 43, .INSTRUCTION, "Account is immutable" },
        InstructionError.IncorrectAuthority                     => .{ 44, .INSTRUCTION, "Incorrect authority provided" },
        InstructionError.BorshIoError                           => .{ 45, .INSTRUCTION, "Failed to serialize or deserialize account data" },
        InstructionError.AccountNotRentExempt                   => .{ 46, .INSTRUCTION, "An account does not have enough lamports to be rent-exempt" },
        InstructionError.InvalidAccountOwner                    => .{ 47, .INSTRUCTION, "Invalid account owner" },
        InstructionError.ProgramArithmeticOverflow              => .{ 48, .INSTRUCTION, "Program arithmetic overflowed" },
        InstructionError.UnsupportedSysvar                      => .{ 49, .INSTRUCTION, "Unsupported sysvar" },
        InstructionError.IllegalOwner                           => .{ 50, .INSTRUCTION, "Provided owner is not allowed" },
        InstructionError.MaxAccountsDataAllocationsExceeded     => .{ 51, .INSTRUCTION, "Accounts data allocations exceeded the maximum allowed per transaction" },
        InstructionError.MaxAccountsExceeded                    => .{ 52, .INSTRUCTION, "Max accounts exceeded" },
        InstructionError.MaxInstructionTraceLengthExceeded      => .{ 53, .INSTRUCTION, "Max instruction trace length exceeded" },
        InstructionError.BuiltinProgramsMustConsumeComputeUnits => .{ 54, .INSTRUCTION, "Builtin programs must consume compute units" },
        // zig fmt: on
        else => {
            std.debug.print("Sig error: {s}\n", .{@errorName(err)});
            return error.SigError;
        },
    };
}

pub fn copyPrefix(dst: []u8, prefix: []const u8) void {
    const size = @min(dst.len, prefix.len);
    @memcpy(dst[0..size], prefix[0..size]);
}
