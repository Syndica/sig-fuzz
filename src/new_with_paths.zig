const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");

const builtins = @import("builtins.zig");
const verify_transaction = @import("verify_transaction.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const bincode = sig.bincode;
const features = sig.runtime.features;
const program = sig.runtime.program;
const sysvars = sig.runtime.sysvar;
const vm = sig.vm;
const update_sysvar = sig.replay.update_sysvar;

const AccountsDb = sig.accounts_db.AccountsDB;

const Account = sig.core.Account;
const Ancestors = sig.core.Ancestors;
const BlockhashQueue = sig.core.BlockhashQueue;
const Epoch = sig.core.Epoch;
const EpochStakes = sig.core.EpochStakes;
const EpochStakesMap = sig.core.EpochStakesMap;
const FeeRateGovernor = sig.core.FeeRateGovernor;
const GenesisConfig = sig.core.GenesisConfig;
const Hash = sig.core.Hash;
const HardForks = sig.core.HardForks;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const Slot = sig.core.Slot;
const Signature = sig.core.Signature;
const StatusCache = sig.core.StatusCache;
const StakesCache = sig.core.StakesCache;
const Transaction = sig.core.Transaction;
const TransactionVersion = sig.core.transaction.Version;
const TransactionMessage = sig.core.transaction.Message;
const TransactionInstruction = sig.core.transaction.Instruction;
const TransactionAddressLookup = sig.core.transaction.AddressLookup;

const AccountSharedData = sig.runtime.AccountSharedData;
const Clock = sig.runtime.sysvar.Clock;
const ComputeBudget = sig.runtime.ComputeBudget;
const EpochSchedule = sig.runtime.sysvar.EpochSchedule;
const FeatureSet = sig.runtime.features.FeatureSet;
const LastRestartSlot = sig.runtime.sysvar.LastRestartSlot;
const RecentBlockhashes = sig.runtime.sysvar.RecentBlockhashes;
const Rent = sig.runtime.sysvar.Rent;
const SlotHashes = sig.runtime.sysvar.SlotHashes;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const SysvarCache = sig.runtime.SysvarCache;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;

const loadTestAccountsDB = sig.accounts_db.db.loadTestAccountsDbEmpty;
const fillMissingSysvarCacheEntries = sig.replay.update_sysvar.fillMissingSysvarCacheEntries;
const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

/// A minimal implementation of `Bank::new_with_paths` for fuzzing purposes.
/// If a fixture hits an error, we may need to implement the missing logic.
/// https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/bank.rs#L1162
pub fn newWithPaths(
    allocator: Allocator,
) !void {
    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.addSlot(allocator, 0);

    // bank.compute_budget = runtime_config.compute_budget;
    // bank.transaction_account_lock_limit = null;
    // bank.transaction_debug_keys = null;
    // bank.cluster_type = genesis_config.cluster_type;
    // bank.feature_set = feature_set;

    try processGenesisConfig();

    try finishInit();

    // Add epoch stakes for all epochs up to the banks slot using banks stakes cache
    // The bank slot is 0 and stakes cache is empty, so we add default epoch stakes.
    for (0..epoch_schedule.getLeaderScheduleEpoch(epoch)) |e| {
        try epoch_stakes_map.put(allocator, e, try .init(allocator));
    }

    const update_sysvar_deps = update_sysvar.UpdateSysvarAccountDeps{
        .accounts_db = &accounts_db,
        .capitalization = &capitalization,
        .ancestors = &ancestors,
        .rent = &genesis_config.rent,
        .slot = slot,
    };

    try update_sysvar.updateStakeHistory(
        allocator,
        .{
            .epoch = epoch,
            .parent_epoch = null, // no parent yet
            .stakes_cache = &stakes_cache,
            .update_sysvar_deps = update_sysvar_deps,
        },
    );
    try update_sysvar.updateClock(allocator, .{
        .feature_set = &feature_set,
        .epoch_schedule = &epoch_schedule,
        .epoch_stakes_map = &epoch_stakes_map,
        .stakes_cache = &stakes_cache,
        .epoch = epoch,
        .parent_epoch = null, // no parent yet
        .genesis_creation_time = genesis_config.creation_time,
        .ns_per_slot = @intCast(genesis_config.nsPerSlot()),
        .update_sysvar_deps = update_sysvar_deps,
    });
    try update_sysvar.updateRent(allocator, genesis_config.rent, update_sysvar_deps);
    try update_sysvar.updateEpochSchedule(allocator, epoch_schedule, update_sysvar_deps);
    try update_sysvar.updateRecentBlockhashes(allocator, &blockhash_queue, update_sysvar_deps);
    try update_sysvar.updateLastRestartSlot(allocator, &feature_set, &hard_forks, update_sysvar_deps);
    try update_sysvar.fillMissingSysvarCacheEntries(allocator, &accounts_db, &ancestors, &sysvar_cache);
}

/// A minimal implementation of `Bank::process_genesis_config` for fuzzing purposes.
/// If a fixture hits an error, we may need to implement the missing logic.
/// https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/bank.rs#L2727
fn processGenesisConfig() !void {
    // Set the feee rate governor
    fee_rate_govenor = genesis_config.fee_rate_governor;

    // Insert genesis config accounts
    var genesis_account_iterator = genesis_config.accounts.iterator();
    while (genesis_account_iterator.next()) |kv| {
        const account = try accountSharedDataFromAccount(allocator, kv.value_ptr);
        defer account.deinit(allocator);
        try accounts_db.putAccount(
            slot,
            kv.key_ptr.*,
            account,
        );
    }

    // Insert genesis config rewards pool accounts
    std.debug.assert(genesis_config.rewards_pools.count() == 0);

    // Set the collector id
    // bank.collector_id = fee_collector;

    // Add genesis hash to blockhash queue, for transaction fuzzing the genesis hash
    // is the first blockhash in the blockhashes list
    blockhash_queue = BlockhashQueue.DEFAULT;
    errdefer blockhash_queue.deinit(allocator);
    try blockhash_queue.insertGenesisHash(
        allocator,
        blockhashes[0], // genesis_config.hash() for production
        fee_rate_govenor.lamports_per_signature,
    );

    // Set misc bank fields
    // const hashes_per_tick = genesis_config.hashes_per_tick;
    // const ticks_per_slot = genesis_config.ticks_per_slot;
    // const ns_per_slot = genesis_config.ns_per_slot;
    // const genesis_creation_time = genesis_config.creation_time;
    // const max_tick_height = (slot + 1) * ticks_per_slot;
    // const slots_per_year = genesis_config.slots_per_year;
    epoch_schedule = genesis_config.epoch_schedule;
    // const inflation = genesis_config.inflation;
    // const rent_collector = RentCollector{
    //     .epoch = epoch,
    //     .epoch_schedule = epoch_schedule,
    //     .slots_per_year = slots_per_year,
    //     .rent = genesis_config.rent,
    // };

    // add builtin programs specefied in genesis config
    std.debug.assert(genesis_config.native_instruction_processors.items.len == 0);
}

fn finishInit() !void {
    // Bank::finish_init(...)
    // https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/bank.rs#L4863

    // Set reward pool pubkeys
    std.debug.assert(genesis_config.rewards_pools.count() == 0);

    try bank_methods.applyFeatureActivations(
        allocator,
        slot,
        &feature_set,
        &accounts_db,
        false,
    );

    // TODO: This gets hit
    // Set limits for 50m block limits
    // if (feature_set.active.contains(features.RAISE_BLOCK_LIMITS_TO_50M)) {
    //     @panic("set limits not implemented");
    // }

    // TODO: This gets hit
    // Set limits for 60m block limits
    // if (feature_set.active.contains(features.RAISE_BLOCK_LIMITS_TO_60M)) {
    //     @panic("set limits not implemented");
    // }

    // NOTE: This should not impact txn fuzzing
    // If the accounts delta hash is still in use, start the background account hasher
    // if (!feature_set.active.contains(features.REMOVE_ACCOUNTS_DELTA_HASH)) {
    //     // start background account hasher
    //     @panic("background account hasher not implemented");
    // }

    // Add builtin programs
    for (builtins.BUILTINS) |builtin_program| {
        // If the feature id is not null, and the builtin program is not migrated, add
        // to the builtin accounts map. If the builtin program has been migrated it will
        // have an entry in accounts db with owner bpf_loader.v3.ID (i.e. it is now a BPF program).
        // For fuzzing purposes, accounts db is currently empty so we do not need to check if
        // the builtin program is migrated or not.
        const builtin_is_bpf_program = if (try accounts_db.getAccountWithAncestors(
            &builtin_program.program_id,
            &ancestors,
        )) |account| blk: {
            defer account.deinit(allocator);
            break :blk account.owner.equals(&program.bpf_loader.v3.ID);
        } else false;

        if (builtin_program.enable_feature_id != null or builtin_is_bpf_program) continue;

        const data = try allocator.dupe(u8, builtin_program.data);
        defer allocator.free(data);

        try accounts_db.putAccount(
            slot,
            builtin_program.program_id,
            .{
                .lamports = 1,
                .data = data,
                .executable = true,
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                .rent_epoch = 0,
            },
        );
    }

    // Add precompiles
    for (program.precompiles.PRECOMPILES) |precompile| {
        if (precompile.required_feature != null) continue;
        // const data = try allocator.dupe(u8, &.{});
        // defer allocator.free(data);
        try accounts_db.putAccount(slot, precompile.program_id, .{
            .lamports = 1,
            .data = &.{},
            .executable = true,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .rent_epoch = 0,
        });
    }

    vm_environment = try vm.Environment.initV1(
        allocator,
        &feature_set,
        &compute_budget,
        false,
        false,
    );
}
