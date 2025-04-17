const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");

const ManagedString = @import("protobuf").ManagedString;

const features = sig.runtime.features;
const executor = sig.runtime.executor;
const sysvar = sig.runtime.sysvar;

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
    ec.* = sig.runtime.transaction_context.EpochContext{
        .allocator = allocator,
        .feature_set = try createFeatureSet(allocator, instr_ctx),
    };

    const sc = try allocator.create(SlotContext);
    sc.* = sig.runtime.transaction_context.SlotContext{
        .allocator = allocator,
        .ec = ec,
        .sysvar_cache = try createSysvarCache(allocator, instr_ctx),
    };

    const tc = try allocator.create(TransactionContext);
    tc.* = sig.runtime.transaction_context.TransactionContext{
        .allocator = allocator,
        .ec = ec,
        .sc = sc,
        .accounts = try createTransactionContextAccounts(
            allocator,
            instr_ctx.accounts.items,
        ),
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
    sysvar_cache.epoch_schedule = try cloneSysvarData(allocator, ctx, sysvar.EpochSchedule.ID);
    if (sysvar_cache.epoch_schedule == null) {
        sysvar_cache.epoch_schedule = try sig.bincode.writeAlloc(
            allocator,
            sysvar.EpochSchedule.DEFAULT,
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
