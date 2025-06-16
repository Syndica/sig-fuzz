const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");
const protobuf = @import("protobuf");

const sysvar = sig.runtime.sysvar;
const features = sig.runtime.features;
const bpf_loader = sig.runtime.program.bpf_loader;
const program_loader = sig.runtime.program_loader;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const EpochStakes = sig.core.stake.EpochStakes;
const AccountSharedData = sig.runtime.AccountSharedData;
const ComputeBudget = sig.runtime.ComputeBudget;
const SysvarCache = sig.runtime.SysvarCache;
const FeatureSet = sig.runtime.FeatureSet;
const TransactionContext = sig.runtime.TransactionContext;
const InstructionInfo = sig.runtime.InstructionInfo;
const VmEnvironment = sig.vm.Environment;
const ProgramMap = sig.runtime.program_loader.ProgramMap;
const TransactionContextAccount = sig.runtime.transaction_context.TransactionContextAccount;
const LogCollector = sig.runtime.LogCollector;
const Rent = sig.runtime.sysvar.Rent;

const ManagedString = protobuf.ManagedString;

pub fn parsePubkey(address: ManagedString) !Pubkey {
    if (address.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
    return .{ .data = address.getSlice()[0..Pubkey.SIZE].* };
}

pub fn loadAccounts(
    allocator: std.mem.Allocator,
    instruction_context: *const pb.InstrContext,
) !std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData) {
    const program_pubkey = try parsePubkey(instruction_context.program_id);

    var accounts = std.AutoArrayHashMapUnmanaged(
        Pubkey,
        AccountSharedData,
    ){};
    errdefer {
        for (accounts.values()) |acc| allocator.free(acc.data);
        accounts.deinit(allocator);
    }

    for (instruction_context.accounts.items) |account| {
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
    instruction_context: *const pb.InstrContext,
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
    instruction_context: *const pb.InstrContext,
) !SysvarCache {
    var sysvar_cache = sig.runtime.SysvarCache{};

    sysvar_cache.clock = try loadSysvar(
        allocator,
        instruction_context,
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
        instruction_context,
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
        instruction_context,
        sysvar.EpochRewards.ID,
    );
    if (std.meta.isError(sysvar_cache.get(sysvar.EpochRewards))) {
        sysvar_cache.epoch_rewards = null;
    }

    sysvar_cache.rent = try loadSysvar(
        allocator,
        instruction_context,
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
        instruction_context,
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
        instruction_context,
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
        instruction_context,
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
        instruction_context,
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
        instruction_context,
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
    instruction_context: *const pb.InstrContext,
    sysvar_pubkey: Pubkey,
) !?[]const u8 {
    for (instruction_context.accounts.items) |account| {
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
    protobuf_instruction_context: *const pb.InstrContext,
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

/// Create a transaction context from the protobuf instruction context.
/// The created transaction context owns all const references.
pub fn createTransactionContext(
    allocator: std.mem.Allocator,
    transaction_context: *TransactionContext,
    loaded_accounts: *const std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
    instruction_context: *const pb.InstrContext,
    mutable_feature_set: ?*FeatureSet,
) !void {
    const feature_set: *FeatureSet = if (mutable_feature_set) |ptr|
        ptr
    else
        try allocator.create(FeatureSet);
    feature_set.* = try loadFeatureSet(allocator, instruction_context);

    const epoch_stakes: *EpochStakes = try allocator.create(EpochStakes);
    epoch_stakes.* = try EpochStakes.initEmpty(allocator);

    const sysvar_cache: *SysvarCache = try allocator.create(SysvarCache);
    sysvar_cache.* = try loadSysvarCache(allocator, instruction_context);

    const vm_environment: *VmEnvironment = try allocator.create(VmEnvironment);
    vm_environment.* = try VmEnvironment.initV1(
        allocator,
        feature_set,
        &ComputeBudget.default(1_400_000),
        false,
        false,
    );

    const program_map: *ProgramMap = try allocator.create(ProgramMap);
    program_map.* = ProgramMap{};
    const slot = (try sysvar_cache.get(sysvar.Clock)).slot;
    for (loaded_accounts.keys(), loaded_accounts.values()) |pubkey, account| {
        if (!pubkey.equals(&bpf_loader.v1.ID) and
            !pubkey.equals(&bpf_loader.v2.ID) and
            !pubkey.equals(&bpf_loader.v3.ID) and
            !pubkey.equals(&bpf_loader.v4.ID)) continue;

        try program_map.put(allocator, pubkey, try program_loader.loadProgram(
            allocator,
            &account,
            loaded_accounts,
            vm_environment,
            slot,
        ));
    }

    const transaction_context_accounts = try allocator.alloc(
        TransactionContextAccount,
        instruction_context.accounts.items.len,
    );
    for (instruction_context.accounts.items, 0..) |account, i| {
        const pubkey = try parsePubkey(account.address);
        transaction_context_accounts[i] = TransactionContextAccount{
            .pubkey = pubkey,
            .account = loaded_accounts.getPtr(pubkey).?,
        };
    }

    const rent = try sysvar_cache.get(sysvar.Rent);
    if (rent.lamports_per_byte_year > std.math.maxInt(u32) or
        rent.exemption_threshold > 999.0 or
        rent.exemption_threshold < 0.0 or
        rent.burn_percent > 100)
    {
        return error.InvalidRent;
    }

    const maybe_recent_blockhashes = sysvar_cache.get(sysvar.RecentBlockhashes) catch null;
    const maybe_last_entry = if (maybe_recent_blockhashes) |rb| rb.last() else null;
    const prev_blockhash, const prev_lamports_per_signature = if (maybe_last_entry) |entry|
        .{ entry.blockhash, entry.fee_calculator.lamports_per_signature }
    else
        .{ Hash.ZEROES, 0 };

    transaction_context.* = .{
        .allocator = allocator,
        .feature_set = feature_set,
        .epoch_stakes = epoch_stakes,
        .sysvar_cache = sysvar_cache,
        .vm_environment = vm_environment,
        .next_vm_environment = vm_environment,
        .program_map = program_map,
        .accounts = transaction_context_accounts,
        .compute_meter = instruction_context.cu_avail,
        .compute_budget = ComputeBudget.default(instruction_context.cu_avail),
        .log_collector = LogCollector.default(),
        .prev_blockhash = prev_blockhash,
        .prev_lamports_per_signature = prev_lamports_per_signature,
        .rent = rent,
    };
}

pub fn deinitTransactionContext(
    allocator: std.mem.Allocator,
    transaction_context: TransactionContext,
) void {
    transaction_context.feature_set.deinit(allocator);
    allocator.destroy(transaction_context.feature_set);

    transaction_context.epoch_stakes.deinit(allocator);
    allocator.destroy(transaction_context.epoch_stakes);

    transaction_context.sysvar_cache.deinit(allocator);
    allocator.destroy(transaction_context.sysvar_cache);

    var vm_environment = transaction_context.vm_environment.*;
    vm_environment.deinit(allocator);
    allocator.destroy(transaction_context.vm_environment);

    var program_map = transaction_context.program_map.*;
    for (program_map.values()) |program| program.deinit(allocator);
    program_map.deinit(allocator);
    allocator.destroy(transaction_context.program_map);

    transaction_context.deinit();
}
