const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");

const ManagedString = @import("protobuf").ManagedString;

const features = sig.runtime.features;
const executor = sig.runtime.executor;
const sysvar = sig.runtime.sysvar;

const InstructionError = sig.core.instruction.InstructionError;
const InstructionInfo = sig.runtime.instruction_info.InstructionInfo;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;
const TransactionContextAccount = sig.runtime.transaction_context.TransactionContextAccount;

const Pubkey = sig.core.Pubkey;

const intFromInstructionError = sig.core.instruction.intFromInstructionError;

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
    var ctx = pb.InstrContext.decode(
        in_slice,
        decode_arena.allocator(),
    ) catch return 0;
    defer ctx.deinit();

    // printPbInstrContext(ctx) catch |err| {
    //     std.debug.print("printPbInstrContext err: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result = executeInstrProto(allocator, ctx) catch |err| {
        std.debug.print("err: {s}\n", .{@errorName(err)});
        return 0;
    };

    // printPbInstrEffects(result) catch |err| {
    //     std.debug.print("printPbInstrEffects err: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result_bytes = try result.encode(allocator);
    defer allocator.free(result_bytes);

    const out_slice = out_ptr[0..out_size.*];
    if (result_bytes.len > out_slice.len) {
        return 0;
    }
    @memcpy(out_slice[0..result_bytes.len], result_bytes);
    out_size.* = result_bytes.len;

    return 1;
}

/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/98f939ba8afcb1b7a5af4316c6085f92111b62a7/src/lib.rs#L473-L474
fn executeInstrProto(allocator: std.mem.Allocator, ctx: pb.InstrContext) !pb.InstrEffects {
    // Create the execution contexts from the protobuf InstrContext
    // [fd] https://github.com/firedancer-io/firedancer/blob/b5acf851f523ec10a85e1b0c8756b2aea477107e/src/flamenco/runtime/tests/fd_exec_instr_test.c#L359-L360
    const ec = sig.runtime.transaction_context.EpochContext{
        .allocator = allocator,
        .feature_set = if (ctx.epoch_context) |epoch_context|
            if (epoch_context.features) |feats|
                try createFeatureSet(allocator, feats)
            else
                features.FeatureSet.EMPTY
        else
            features.FeatureSet.EMPTY,
    };
    defer ec.deinit();

    var sc = sig.runtime.transaction_context.SlotContext{
        .ec = &ec,
        .sysvar_cache = sig.runtime.SysvarCache{},
    };
    fillMissingEntries(allocator, &sc.sysvar_cache, ctx);

    var tc = sig.runtime.transaction_context.TransactionContext{
        .allocator = allocator,
        .sc = &sc,
        .accounts = try createTransactionContextAccounts(
            allocator,
            ctx.accounts.items,
        ),
        .instruction_stack = .{},
        .instruction_trace = .{},
        .return_data = .{},
        .accounts_resize_delta = 0,
        .compute_meter = ctx.cu_avail,
        .compute_budget = sig.runtime.ComputeBudget.default(ctx.cu_avail),
        .custom_error = null,
        .log_collector = null,
        .prev_blockhash = sig.core.Hash.ZEROES,
        .prev_lamports_per_signature = 0,
    };
    defer tc.deinit();

    const instr_info = try createInstructionInfo(
        allocator,
        &tc,
        .{ .data = ctx.program_id.getSlice()[0..Pubkey.SIZE].* },
        ctx.data.getSlice(),
        ctx.instr_accounts.items,
    );
    defer instr_info.deinit(allocator);

    // Execute the instruction
    // [fd] https://github.com/firedancer-io/firedancer/blob/b5acf851f523ec10a85e1b0c8756b2aea477107e/src/flamenco/runtime/tests/fd_exec_instr_test.c#L1478
    var result: ?InstructionError = null;
    executor.executeInstruction(
        allocator,
        &tc,
        instr_info,
    ) catch |err| {
        switch (err) {
            error.OutOfMemory => return err,
            else => |e| result = e,
        }
    };

    // Capture the instruction effects
    // [fd] https://github.com/firedancer-io/firedancer/blob/b5acf851f523ec10a85e1b0c8756b2aea477107e/src/flamenco/runtime/tests/fd_exec_instr_test.c#L1480-L1572
    return createInstrEffects(
        allocator,
        &tc,
        result,
    );
}

fn createInstrEffects(
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

fn createFeatureSet(
    allocator: std.mem.Allocator,
    pb_feature_set: pb.FeatureSet,
) !features.FeatureSet {
    var indexed_features = std.AutoArrayHashMap(u64, Pubkey).init(allocator);
    defer indexed_features.deinit();

    for (features.ALL_FEATURES) |feature| {
        const feature_id = @as(u64, feature.data[0]) |
            @as(u64, feature.data[1]) << 8 |
            @as(u64, feature.data[2]) << 16 |
            @as(u64, feature.data[3]) << 24 |
            @as(u64, feature.data[4]) << 32 |
            @as(u64, feature.data[5]) << 40 |
            @as(u64, feature.data[6]) << 48 |
            @as(u64, feature.data[7]) << 56;
        try indexed_features.put(feature_id, feature);
    }

    var feature_set = features.FeatureSet.EMPTY;
    for (pb_feature_set.features.items) |id| {
        if (indexed_features.get(id)) |pubkey| {
            try feature_set.active.put(allocator, pubkey, 0);
        }
    }

    return feature_set;
}

fn createTransactionContextAccounts(
    allocator: std.mem.Allocator,
    pb_accounts: []const pb.AcctState,
) ![]TransactionContextAccount {
    var accounts = std.ArrayList(TransactionContextAccount).init(allocator);
    errdefer {
        for (accounts.items) |account| account.deinit(allocator);
        accounts.deinit();
    }

    for (pb_accounts) |pb_account| {
        const account_data = try allocator.dupe(u8, pb_account.data.getSlice());
        errdefer allocator.free(account_data);
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

fn createInstructionInfo(
    allocator: std.mem.Allocator,
    tc: *const TransactionContext,
    program_id: Pubkey,
    instruction: []const u8,
    pb_instruction_accounts: []const pb.InstrAcct,
) !InstructionInfo {
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

fn getSysvarData(ctx: pb.InstrContext, pubkey: Pubkey) ?[]const u8 {
    for (ctx.accounts.items) |acc| {
        if (std.mem.eql(u8, acc.address.getSlice(), &pubkey.data)) {
            return acc.data.getSlice();
        }
    }
    return null;
}

pub fn fillMissingEntries(allocator: std.mem.Allocator, sysvar_cache: *sig.runtime.SysvarCache, ctx: pb.InstrContext) void {
    if (sysvar_cache.clock == null) {
        if (getSysvarData(ctx, sysvar.Clock.ID)) |clock_data| {
            sysvar_cache.clock = sig.bincode.readFromSlice(
                allocator,
                sysvar.Clock,
                clock_data,
                .{},
            ) catch null;
        }
    }
    if (sysvar_cache.epoch_rewards == null) {
        if (getSysvarData(ctx, sysvar.EpochRewards.ID)) |epoch_rewards_data| {
            sysvar_cache.epoch_rewards = sig.bincode.readFromSlice(
                allocator,
                sysvar.EpochRewards,
                epoch_rewards_data,
                .{},
            ) catch null;
        }
    }
    if (sysvar_cache.epoch_schedule == null) {
        if (getSysvarData(ctx, sysvar.EpochSchedule.ID)) |epoch_schedule_data| {
            sysvar_cache.epoch_schedule = sig.bincode.readFromSlice(
                allocator,
                sysvar.EpochSchedule,
                epoch_schedule_data,
                .{},
            ) catch null;
        }
    }
    if (sysvar_cache.last_restart_slot == null) {
        if (getSysvarData(ctx, sysvar.LastRestartSlot.ID)) |last_restart_slot_data| {
            sysvar_cache.last_restart_slot = sig.bincode.readFromSlice(
                allocator,
                sysvar.LastRestartSlot,
                last_restart_slot_data,
                .{},
            ) catch null;
        }
    }
    if (sysvar_cache.rent == null) {
        if (getSysvarData(ctx, sysvar.Rent.ID)) |rent_data| {
            sysvar_cache.rent = sig.bincode.readFromSlice(
                allocator,
                sysvar.Rent,
                rent_data,
                .{},
            ) catch null;
        }
    }
    if (sysvar_cache.slot_hashes == null) {
        if (getSysvarData(ctx, sysvar.SlotHashes.ID)) |slot_hashes_data| {
            sysvar_cache.slot_hashes = sig.bincode.readFromSlice(
                allocator,
                sysvar.SlotHashes,
                slot_hashes_data,
                .{},
            ) catch null;
        }
    }
    if (sysvar_cache.stake_history == null) {
        if (getSysvarData(ctx, sysvar.StakeHistory.ID)) |stake_history_data| {
            sysvar_cache.stake_history = sig.bincode.readFromSlice(
                allocator,
                sysvar.StakeHistory,
                stake_history_data,
                .{},
            ) catch null;
        }
    }
    if (sysvar_cache.fees == null) {
        if (getSysvarData(ctx, sysvar.Fees.ID)) |fees_data| {
            sysvar_cache.fees = sig.bincode.readFromSlice(
                allocator,
                sysvar.Fees,
                fees_data,
                .{},
            ) catch null;
        }
    }
    if (sysvar_cache.recent_blockhashes == null) {
        if (getSysvarData(ctx, sysvar.RecentBlockhashes.ID)) |recent_blockhashes_data| {
            sysvar_cache.recent_blockhashes = sig.bincode.readFromSlice(
                allocator,
                sysvar.RecentBlockhashes,
                recent_blockhashes_data,
                .{},
            ) catch null;
        }
    }
}

test "sol_compat_instr_execute_v1" {
    const system_program = sig.runtime.program.system_program;
    const ids = sig.runtime.ids;

    var prng = std.rand.Random.DefaultPrng.init(0);

    const allocator = std.heap.c_allocator;

    const pb_system_program_id =
        ManagedString.managed(&system_program.ID.data);

    const pb_native_loader_id =
        ManagedString.managed(&ids.NATIVE_LOADER_ID.data);

    const account_0_id = Pubkey.initRandom(prng.random()).data;
    const pb_account_0_id =
        ManagedString.managed(&account_0_id);

    const account_1_id = Pubkey.initRandom(prng.random()).data;
    const pb_account_1_id =
        ManagedString.managed(&account_1_id);

    var pb_accounts = std.ArrayList(pb.AcctState).init(allocator);
    defer pb_accounts.deinit();
    try pb_accounts.appendSlice(&.{
        .{
            .address = pb_account_0_id,
            .lamports = 2_000_000,
            .owner = pb_system_program_id,
        },
        .{
            .address = pb_account_1_id,
            .owner = pb_system_program_id,
        },
        .{
            .address = pb_system_program_id,
            .executable = true,
            .owner = pb_native_loader_id,
        },
    });

    var pb_instr_accounts = std.ArrayList(pb.InstrAcct).init(allocator);
    defer pb_instr_accounts.deinit();
    try pb_instr_accounts.appendSlice(&.{
        .{
            .index = 0,
            .is_signer = true,
            .is_writable = true,
        },
        .{
            .index = 1,
            .is_signer = false,
            .is_writable = true,
        },
    });

    const instruction = system_program.Instruction{
        .transfer = .{
            .lamports = 1_000_000,
        },
    };
    const instruction_data = try sig.bincode.writeAlloc(
        allocator,
        instruction,
        .{},
    );
    defer allocator.free(instruction_data);

    const pb_ic = pb.InstrContext{
        .program_id = pb_system_program_id,
        .accounts = pb_accounts,
        .instr_accounts = pb_instr_accounts,
        .data = ManagedString.managed(instruction_data),
        .cu_avail = 150,
        .slot_context = null,
        .epoch_context = null,
    };

    _ = try executeInstrProto(allocator, pb_ic);
}
