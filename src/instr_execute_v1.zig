const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const protobuf_parse = @import("protobuf_parse.zig");

const executor = sig.runtime.executor;
const sysvar = sig.runtime.sysvar;
const features = sig.runtime.features;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;

// Loader imports
const AccountSharedData = sig.runtime.AccountSharedData;
const bpf_loader = sig.runtime.program.bpf_loader;
const SysvarCache = sig.runtime.SysvarCache;
const program_loader = sig.runtime.program_loader;
const ComputeBudget = sig.runtime.ComputeBudget;
const Hash = sig.core.Hash;
const LoadedProgram = sig.runtime.program_loader.LoadedProgram;
const ProgramMap = sig.runtime.program_loader.ProgramMap;
const VmEnvironment = sig.vm.Environment;
const Syscall = sig.vm.Syscall;
const Registry = sig.vm.Registry;
const EpochStakes = sig.core.stake.EpochStakes;
const FeatureSet = sig.runtime.FeatureSet;
const LogCollector = sig.runtime.LogCollector;
const TransactionContextAccount = sig.runtime.transaction_context.TransactionContextAccount;
const InstructionInfo = sig.runtime.InstructionInfo;

const EMIT_LOGS = false;

/// [fd] https://github.com/firedancer-io/firedancer/blob/0ad2143a9960b7daa5eb594367835d0cbae25657/src/flamenco/runtime/tests/fd_exec_sol_compat.c#L591
/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/98f939ba8afcb1b7a5af4316c6085f92111b62a7/src/lib.rs#L1043
export fn sol_compat_instr_execute_v1(
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
    var pb_instr_ctx = pb.InstrContext.decode(
        in_slice,
        decode_arena.allocator(),
    ) catch |err| {
        std.debug.print("pb.InstrContext.decode: {s}\n", .{@errorName(err)});
        return 0;
    };
    defer pb_instr_ctx.deinit();

    // utils.printPbInstrContext(pb_instr_ctx) catch |err| {
    //     std.debug.print("printPbInstrContext: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result = executeInstruction(allocator, pb_instr_ctx, EMIT_LOGS) catch |err| {
        std.debug.print("executeInstruction: {s}\n", .{@errorName(err)});
        return 0;
    };

    // printPbInstrEffects(result) catch |err| {
    //     std.debug.print("printPbInstrEffects: {s}\n", .{@errorName(err)});
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

/// Load accounts for instruction harness.
/// [agave] https://github.com/firedancer-io/solfuzz-agave/blob/11c04e7e6a1edc014c2f7899311b0ca8e49f9d0c/src/lib.rs#L765-L793
fn loadAccounts(
    allocator: std.mem.Allocator,
    pb_instr_ctx: pb.InstrContext,
) !std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData) {
    const program_pubkey = try protobuf_parse.parsePubkey(pb_instr_ctx.program_id);

    var accounts = std.AutoArrayHashMapUnmanaged(
        Pubkey,
        AccountSharedData,
    ){};
    errdefer {
        for (accounts.values()) |acc| allocator.free(acc.data);
        accounts.deinit(allocator);
    }

    for (pb_instr_ctx.accounts.items) |account| {
        const pubkey = try protobuf_parse.parsePubkey(account.address);

        // If duplicate accounts are present, this account loader must be adjusted.
        if (accounts.contains(pubkey)) return error.DuplicateAccount;

        // TODO: May need to mannually override the owner and executable for bpf conformance
        // [agave] https://github.com/firedancer-io/solfuzz-agave/blob/11c04e7e6a1edc014c2f7899311b0ca8e49f9d0c/src/lib.rs#L776-L791
        // const owner, const executable = if (pubkey.equals(&program_pubkey))
        //     .{ bpf_loader.v3.ID, true }
        // else
        //     .{ try protobuf_parse.parsePubkey(account.owner), account.executable };
        const owner = try protobuf_parse.parsePubkey(account.owner);
        const executable = account.executable;

        try accounts.put(
            allocator,
            pubkey,
            .{
                .lamports = account.lamports,
                .data = try allocator.dupe(u8, account.data.getSlice()),
                .executable = executable,
                .rent_epoch = account.rent_epoch,
                .owner = owner,
            },
        );
    }

    // Add the program account if it does not exist.
    // [agave] https://github.com/firedancer-io/solfuzz-agave/blob/11c04e7e6a1edc014c2f7899311b0ca8e49f9d0c/src/lib.rs#L754-L763
    if (accounts.get(program_pubkey) == null) {
        try accounts.put(allocator, program_pubkey, .{
            .lamports = 0,
            .data = try allocator.dupe(u8, &.{}),
            .executable = false,
            .rent_epoch = 0,
            .owner = Pubkey.ZEROES,
        });
    }

    return accounts;
}

fn loadFeatureSet(allocator: std.mem.Allocator, pb_instr_ctx: pb.InstrContext) !FeatureSet {
    const maybe_pb_features = if (pb_instr_ctx.epoch_context) |epoch_ctx|
        if (epoch_ctx.features) |pb_features| pb_features else null
    else
        null;

    const pb_features = maybe_pb_features orelse return FeatureSet.EMPTY;

    var indexed_features = std.AutoArrayHashMap(u64, Pubkey).init(allocator);
    defer indexed_features.deinit();

    for (features.FEATURES) |feature| {
        try indexed_features.put(@bitCast(feature.data[0..8].*), feature);
    }

    var feature_set = features.FeatureSet.EMPTY;

    for (pb_features.features.items) |id| {
        if (indexed_features.get(id)) |pubkey| {
            try feature_set.active.put(allocator, pubkey, 0);
        }
    }

    return feature_set;
}

/// Populate the sysvar cache using the instruction context accounts and
/// set any necessary defaults if the associated account is not present.
/// Defaults are requried for Clock, EpochSchedule, Rent, LastRestartSlot,
/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/11c04e7e6a1edc014c2f7899311b0ca8e49f9d0c/src/lib.rs#L680-L738
fn loadSysvarCache(
    allocator: std.mem.Allocator,
    instr_ctx: pb.InstrContext,
) !SysvarCache {
    var sysvar_cache = sig.runtime.SysvarCache{};

    sysvar_cache.clock = try loadSysvar(
        allocator,
        instr_ctx,
        sysvar.Clock.ID,
    );
    if (std.meta.isError(sysvar_cache.get(sysvar.Clock))) {
        var clock = sysvar.Clock.DEFAULT;
        clock.slot = 10;
        sysvar_cache.clock = try sysvar.serialize(
            allocator,
            clock,
        );
    }

    sysvar_cache.epoch_schedule = try loadSysvar(
        allocator,
        instr_ctx,
        sysvar.EpochSchedule.ID,
    );
    if (std.meta.isError(sysvar_cache.get(sysvar.EpochSchedule))) {
        sysvar_cache.epoch_schedule = try sysvar.serialize(
            allocator,
            sig.core.EpochSchedule.DEFAULT,
        );
    }

    sysvar_cache.epoch_rewards = try loadSysvar(
        allocator,
        instr_ctx,
        sysvar.EpochRewards.ID,
    );
    if (std.meta.isError(sysvar_cache.get(sysvar.EpochRewards))) {
        sysvar_cache.epoch_rewards = null;
    }

    sysvar_cache.rent = try loadSysvar(
        allocator,
        instr_ctx,
        sysvar.Rent.ID,
    );
    if (std.meta.isError(sysvar_cache.get(sysvar.Rent))) {
        sysvar_cache.rent = try sysvar.serialize(
            allocator,
            sysvar.Rent.DEFAULT,
        );
    }

    sysvar_cache.last_restart_slot = try loadSysvar(
        allocator,
        instr_ctx,
        sysvar.LastRestartSlot.ID,
    );
    if (std.meta.isError(sysvar_cache.get(sysvar.LastRestartSlot))) {
        sysvar_cache.last_restart_slot = try sysvar.serialize(
            allocator,
            sysvar.LastRestartSlot{
                .last_restart_slot = 5000,
            },
        );
    }

    if (try loadSysvar(
        allocator,
        instr_ctx,
        sysvar.SlotHashes.ID,
    )) |slot_hashes| {
        if (sig.bincode.readFromSlice(
            allocator,
            sysvar.SlotHashes,
            slot_hashes,
            .{},
        ) catch null) |slot_hashes_obj| {
            sysvar_cache.slot_hashes = slot_hashes;
            sysvar_cache.slot_hashes_obj = slot_hashes_obj;
        } else {
            allocator.free(slot_hashes);
        }
    }

    if (try loadSysvar(
        allocator,
        instr_ctx,
        sysvar.StakeHistory.ID,
    )) |stake_history_data| {
        if (sig.bincode.readFromSlice(
            allocator,
            sysvar.StakeHistory,
            stake_history_data,
            .{},
        ) catch null) |stake_history_obj| {
            sysvar_cache.stake_history = stake_history_data;
            sysvar_cache.stake_history_obj = stake_history_obj;
        } else {
            allocator.free(stake_history_data);
        }
    }

    if (try loadSysvar(
        allocator,
        instr_ctx,
        sysvar.Fees.ID,
    )) |fees| {
        if (sig.bincode.readFromSlice(
            allocator,
            sysvar.Fees,
            fees,
            .{},
        ) catch null) |fees_obj| {
            sysvar_cache.fees_obj = fees_obj;
        } else {
            allocator.free(fees);
        }
    }

    if (try loadSysvar(
        allocator,
        instr_ctx,
        sysvar.RecentBlockhashes.ID,
    )) |recent_blockhashes| {
        if (sig.bincode.readFromSlice(
            allocator,
            sysvar.RecentBlockhashes,
            recent_blockhashes,
            .{},
        ) catch null) |recent_blockhashes_obj| {
            sysvar_cache.recent_blockhashes_obj = recent_blockhashes_obj;
        } else {
            allocator.free(recent_blockhashes);
        }
    }

    return sysvar_cache;
}

/// Loads bytes for a given sysvar if an associated account is present in the
/// instruction context accounts. Caller owns the returned data.
fn loadSysvar(
    allocator: std.mem.Allocator,
    pb_instr_ctx: pb.InstrContext,
    sysvar_pubkey: Pubkey,
) !?[]const u8 {
    for (pb_instr_ctx.accounts.items) |account| {
        if (account.lamports == 0) continue;
        const account_pubkey = try protobuf_parse.parsePubkey(account.address);
        if (account_pubkey.equals(&sysvar_pubkey)) {
            return try allocator.dupe(u8, account.data.getSlice());
        }
    }
    return null;
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

fn executeInstruction(allocator: std.mem.Allocator, pb_instr_ctx: pb.InstrContext, emit_logs: bool) !pb.InstrEffects {
    errdefer |err| {
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
        std.debug.print("executeInstruction: {s}\n", .{@errorName(err)});
    }

    const accounts = try loadAccounts(allocator, pb_instr_ctx);
    defer {
        for (accounts.values()) |acc| allocator.free(acc.data);
        var accs = accounts;
        accs.deinit(allocator);
    }

    const feature_set = try loadFeatureSet(allocator, pb_instr_ctx);
    defer feature_set.deinit(allocator);

    const epoch_stakes = try EpochStakes.initEmpty(allocator);
    defer epoch_stakes.deinit(allocator);

    const sysvar_cache = try loadSysvarCache(allocator, pb_instr_ctx);
    defer sysvar_cache.deinit(allocator);

    const compute_budget = ComputeBudget.default(pb_instr_ctx.cu_avail);

    const vm_environment = try VmEnvironment.initV1(
        allocator,
        &feature_set,
        &compute_budget,
        false,
        false,
    );
    defer vm_environment.deinit(allocator);

    const clock = try sysvar_cache.get(sysvar.Clock);
    const epoch_schedule = try sysvar_cache.get(sysvar.EpochSchedule);
    const rent = try sysvar_cache.get(sysvar.Rent);

    const maybe_recent_blockhashes = sysvar_cache.get(sysvar.RecentBlockhashes) catch null;
    const maybe_last_entry = if (maybe_recent_blockhashes) |rb| rb.last() else null;
    const blockhash, const lamports_per_signature = if (maybe_last_entry) |entry|
        .{ entry.blockhash, entry.fee_calculator.lamports_per_signature }
    else
        .{ Hash.ZEROES, 0 };

    if (rent.lamports_per_byte_year > std.math.maxInt(u32) or
        rent.exemption_threshold > 999.0 or
        rent.exemption_threshold < 0.0 or
        rent.burn_percent > 100)
    {
        return error.InvalidRent;
    }

    var program_map = ProgramMap{};
    defer {
        for (program_map.values()) |v| v.deinit(allocator);
        program_map.deinit(allocator);
    }

    for (accounts.keys(), accounts.values()) |pubkey, account| {
        if (!pubkey.equals(&bpf_loader.v1.ID) and
            !pubkey.equals(&bpf_loader.v2.ID) and
            !pubkey.equals(&bpf_loader.v3.ID) and
            !pubkey.equals(&bpf_loader.v4.ID)) continue;

        try program_map.put(allocator, pubkey, try program_loader.loadProgram(
            allocator,
            &account,
            &accounts,
            &vm_environment,
            clock.slot,
        ));
    }

    const txn_accounts = try allocator.alloc(
        TransactionContextAccount,
        pb_instr_ctx.accounts.items.len,
    );
    for (pb_instr_ctx.accounts.items, 0..) |account, i| {
        const pubkey = try protobuf_parse.parsePubkey(account.address);
        txn_accounts[i] = TransactionContextAccount{
            .pubkey = pubkey,
            .account = accounts.getPtr(pubkey).?,
        };
    }

    var tc = TransactionContext{
        .allocator = allocator,
        .feature_set = &feature_set,
        .epoch_stakes = &epoch_stakes,
        .sysvar_cache = &sysvar_cache,
        .vm_environment = &vm_environment,
        .next_vm_environment = null,
        .program_map = &program_map,
        .accounts = txn_accounts,
        .compute_meter = compute_budget.compute_unit_limit,
        .compute_budget = compute_budget,
        .log_collector = LogCollector.default(),
        .prev_blockhash = blockhash,
        .prev_lamports_per_signature = lamports_per_signature,
        .rent = rent,
    };
    defer tc.deinit();

    const instr_info = try createInstructionInfo(
        allocator,
        &tc,
        try protobuf_parse.parsePubkey(pb_instr_ctx.program_id),
        pb_instr_ctx.data.getSlice(),
        pb_instr_ctx.instr_accounts.items,
    );
    defer instr_info.deinit(allocator);

    var result: ?InstructionError = null;
    executor.executeInstruction(
        allocator,
        &tc,
        instr_info,
    ) catch |err| {
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| result = e,
        }
    };

    if (emit_logs) {
        std.debug.print("Execution Logs:\n", .{});
        for (tc.log_collector.?.collect(), 1..) |msg, index| {
            std.debug.print("    {}: {s}\n", .{ index, msg });
        }
    }

    _ = epoch_schedule;

    return createInstrEffects(
        allocator,
        &tc,
        result,
    );
}

const ManagedString = @import("protobuf").ManagedString;
const intFromInstructionError = sig.core.instruction.intFromInstructionError;

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
