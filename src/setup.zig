const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");
const protobuf = @import("protobuf");

const sysvar = sig.runtime.sysvar;
const features = sig.runtime.features;
const bpf_loader = sig.runtime.program.bpf_loader;

const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;
const SysvarCache = sig.runtime.SysvarCache;
const FeatureSet = sig.runtime.FeatureSet;
const TransactionContext = sig.runtime.TransactionContext;
const InstructionInfo = sig.runtime.InstructionInfo;

const ManagedString = protobuf.ManagedString;

pub fn parsePubkey(
    address: ManagedString,
) !Pubkey {
    if (address.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
    return .{ .data = address.getSlice()[0..Pubkey.SIZE].* };
}

/// Load accounts for instruction harness.
/// [agave] https://github.com/firedancer-io/solfuzz-agave/blob/11c04e7e6a1edc014c2f7899311b0ca8e49f9d0c/src/lib.rs#L765-L793
pub fn loadAccounts(
    allocator: std.mem.Allocator,
    pb_instr_ctx: pb.InstrContext,
) !std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData) {
    const program_pubkey = try parsePubkey(pb_instr_ctx.program_id);

    var accounts = std.AutoArrayHashMapUnmanaged(
        Pubkey,
        AccountSharedData,
    ){};
    errdefer {
        for (accounts.values()) |acc| allocator.free(acc.data);
        accounts.deinit(allocator);
    }

    for (pb_instr_ctx.accounts.items) |account| {
        const pubkey = try parsePubkey(account.address);

        // If duplicate accounts are present, this account loader must be adjusted.
        if (accounts.contains(pubkey)) return error.DuplicateAccount;

        // TODO: May need to mannually override the owner and executable for bpf conformance
        // [agave] https://github.com/firedancer-io/solfuzz-agave/blob/11c04e7e6a1edc014c2f7899311b0ca8e49f9d0c/src/lib.rs#L776-L791
        // const owner, const executable = if (pubkey.equals(&program_pubkey))
        //     .{ bpf_loader.v3.ID, true }
        // else
        //     .{ try parsePubkey(account.owner), account.executable };
        const owner = try parsePubkey(account.owner);
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

pub fn loadFeatureSet(
    allocator: std.mem.Allocator,
    instruction_context: pb.InstrContext,
) !FeatureSet {
    const maybe_pb_features = if (instruction_context.epoch_context) |epoch_ctx|
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

pub fn loadSysvarCache(
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

pub fn loadSysvar(
    allocator: std.mem.Allocator,
    pb_instr_ctx: pb.InstrContext,
    sysvar_pubkey: Pubkey,
) !?[]const u8 {
    for (pb_instr_ctx.accounts.items) |account| {
        if (account.lamports == 0) continue;
        const account_pubkey = try parsePubkey(account.address);
        if (account_pubkey.equals(&sysvar_pubkey)) {
            return try allocator.dupe(u8, account.data.getSlice());
        }
    }
    return null;
}

pub fn createInstructionInfo(
    allocator: std.mem.Allocator,
    transaction_context: *const TransactionContext,
    protobuf_instruction_context: pb.InstrContext,
) !InstructionInfo {
    const program_id = try parsePubkey(protobuf_instruction_context.program_id);
    const instr_accounts = protobuf_instruction_context.instr_accounts.items;
    const instruction_data = try allocator.dupe(u8, protobuf_instruction_context.data.getSlice());

    const program_index_in_transaction = blk: {
        for (transaction_context.accounts, 0..) |acc, i| {
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

    for (instr_accounts, 0..) |acc, idx| {
        if (acc.index >= transaction_context.accounts.len)
            return error.AccountIndexOutOfBounds;

        const index_in_callee = blk: {
            for (0..idx) |i| {
                if (acc.index ==
                    instr_accounts[i].index)
                {
                    break :blk i;
                }
            }
            break :blk idx;
        };

        try account_metas.append(.{
            .pubkey = transaction_context.accounts[acc.index].pubkey,
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
        .instruction_data = instruction_data,
        .initial_account_lamports = 0,
    };
}
