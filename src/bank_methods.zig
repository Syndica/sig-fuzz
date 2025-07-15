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

pub fn applyFeatureActivations(
    allocator: Allocator,
    slot: u64,
    feature_set: *FeatureSet,
    accounts_db: *AccountsDb,
    allow_new_activations: bool,
) !void {
    const new_feature_activations = try computeActiveFeatureSet(
        allocator,
        slot,
        feature_set,
        accounts_db,
        allow_new_activations,
    );

    // Update activation slot of features in `new_feature_activations`
    for (new_feature_activations.keys()) |feature_id| {
        const db_account = try tryGetAccount(accounts_db, feature_id) orelse continue;
        defer db_account.deinit(allocator);

        const activation_slot = try featureActivationSlotFromAccount(allocator, db_account) orelse continue;

        const account = try accountSharedDataFromAccount(allocator, &db_account);
        defer account.deinit(allocator);

        _ = try bincode.writeToSlice(account.data, activation_slot, .{});

        try accounts_db.putAccount(slot, feature_id, account);
    }

    // Update active set of reserved account keys which are not allowed to be write locked
    // TODO
    // self.reserved_account_keys = {
    //     let mut reserved_keys = ReservedAccountKeys::clone(&self.reserved_account_keys);
    //     reserved_keys.update_active_set(&self.feature_set);
    //     Arc::new(reserved_keys)
    // };

    if (new_feature_activations.contains(features.PICO_INFLATION)) {
        std.debug.print("Activating pico inflation at slot {}\n", .{slot});
        // TODO
        // *self.inflation.write().unwrap() = Inflation::pico();
        // self.fee_rate_governor.burn_percent = 50; // 50% fee burn
        // self.rent_collector.rent.burn_percent = 50; // 50% rent burn
    }

    const is_disjoint = blk: {
        const full_inflation_features = try feature_set.fullInflationFeaturesEnabled(allocator);
        const smaller, const larger = if (new_feature_activations.count() <= full_inflation_features.count())
            .{ new_feature_activations, full_inflation_features }
        else
            .{ full_inflation_features, new_feature_activations };
        for (smaller.keys()) |key| if (larger.contains(key)) break :blk false;
        break :blk true;
    };
    if (!is_disjoint) {
        std.debug.print("Activating full inflation at slot {}\n", .{slot});
        // TODO
        // *self.inflation.write().unwrap() = Inflation::full();
        // self.fee_rate_governor.burn_percent = 50; // 50% fee burn
        // self.rent_collector.rent.burn_percent = 50; // 50% rent burn
    }

    // TODO
    try applyBuiltinProgramFeatureTransitions(
        allocator,
        slot,
        feature_set,
        accounts_db,
        &new_feature_activations,
        allow_new_activations,
    );

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK)) {
        std.debug.print("Activating update hashes per tick at slot {}\n", .{slot});
        // TODO
        // self.apply_updated_hashes_per_tick(DEFAULT_HASHES_PER_TICK);

    }

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK2)) {
        std.debug.print("Activating update hashes per tick 2 at slot {}\n", .{slot});
        // TODO
        // self.apply_updated_hashes_per_tick(UPDATED_HASHES_PER_TICK2);

    }

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK3)) {
        std.debug.print("Activating update hashes per tick 3 at slot {}\n", .{slot});
        // TODO
        // self.apply_updated_hashes_per_tick(UPDATED_HASHES_PER_TICK3);
    }

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK4)) {
        std.debug.print("Activating update hashes per tick 4 at slot {}\n", .{slot});
        // TODO
        // self.apply_updated_hashes_per_tick(UPDATED_HASHES_PER_TICK4);
    }

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK5)) {
        std.debug.print("Activating update hashes per tick 5 at slot {}\n", .{slot});
        // TODO
        // self.apply_updated_hashes_per_tick(UPDATED_HASHES_PER_TICK5);
    }

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK6)) {
        std.debug.print("Activating update hashes per tick 6 at slot {}\n", .{slot});
        // TODO
        // self.apply_updated_hashes_per_tick(UPDATED_HASHES_PER_TICK6);
    }

    if (new_feature_activations.contains(features.ACCOUNTS_LT_HASH)) {
        std.debug.print("Activating accounts lt hash at slot {}\n", .{slot});
        // TODO
        // // Activating the accounts lt hash feature means we need to have an accounts lt hash
        // // value at the end of this if-block.  If the cli arg has been used, that means we
        // // already have an accounts lt hash and do not need to recalculate it.
        // if self
        //     .rc
        //     .accounts
        //     .accounts_db
        //     .is_experimental_accumulator_hash_enabled()
        // {
        //     // We already have an accounts lt hash value, so no need to recalculate it.
        //     // Nothing else to do here.
        // } else {
        //     let parent_slot = self.parent_slot;
        //     info!(
        //         "Calculating the accounts lt hash for slot {parent_slot} \
        //             as part of feature activation; this may take some time...",
        //     );
        //     // We must calculate the accounts lt hash now as part of feature activation.
        //     // Note, this bank is *not* frozen yet, which means it will later call
        //     // `update_accounts_lt_hash()`.  Therefore, we calculate the accounts lt hash based
        //     // on *our parent*, not us!
        //     let parent_ancestors = {
        //         let mut ancestors = self.ancestors.clone();
        //         ancestors.remove(&self.slot());
        //         ancestors
        //     };
        //     let (parent_accounts_lt_hash, duration) = meas_dur!({
        //         self.rc
        //             .accounts
        //             .accounts_db
        //             .calculate_accounts_lt_hash_at_startup_from_index(
        //                 &parent_ancestors,
        //                 parent_slot,
        //             )
        //     });
        //     *self.accounts_lt_hash.get_mut().unwrap() = parent_accounts_lt_hash;
        //     info!(
        //         "Calculating the accounts lt hash for slot {parent_slot} \
        //             completed in {duration:?}, accounts_lt_hash checksum: {}",
        //         self.accounts_lt_hash.get_mut().unwrap().0.checksum(),
        //     );
        // }
    }

    if (new_feature_activations.contains(features.RAISE_BLOCK_LIMITS_TO_50M) and
        !feature_set.active.contains(features.RAISE_BLOCK_LIMITS_TO_60M))
    {
        std.debug.print("Activating raise block limits to 50M at slot {}\n", .{slot});
        // TODO
        // let (account_cost_limit, block_cost_limit, vote_cost_limit) = simd_0207_block_limits();
        // self.write_cost_tracker().unwrap().set_limits(
        //     account_cost_limit,
        //     block_cost_limit,
        //     vote_cost_limit,
        // );

    }

    if (new_feature_activations.contains(features.RAISE_BLOCK_LIMITS_TO_60M)) {
        std.debug.print("Activating raise block limits to 60M at slot {}\n", .{slot});
        // TODO
        // let (account_cost_limit, block_cost_limit, vote_cost_limit) = simd_0256_block_limits();
        // self.write_cost_tracker().unwrap().set_limits(
        //     account_cost_limit,
        //     block_cost_limit,
        //     vote_cost_limit,
        // );

    }

    if (new_feature_activations.contains(features.REMOVE_ACCOUNTS_DELTA_HASH)) {
        std.debug.print("Removing accounts delta hash at slot {}\n", .{slot});
        // TODO
        // // If the accounts delta hash has been removed, then we no longer need to compute the
        // // AccountHash for modified accounts, and can stop the background account hasher.
        // self.rc.accounts.accounts_db.stop_background_hasher();
    }
}

fn applyBuiltinProgramFeatureTransitions(
    allocator: Allocator,
    slot: Slot,
    feature_set: *const FeatureSet,
    accounts_db: *AccountsDb,
    new_feature_activations: *const std.AutoArrayHashMapUnmanaged(Pubkey, void),
    allow_new_activations: bool,
) !void {
    for (builtins.BUILTINS) |builtin_program| {
        var is_core_bpf = false;
        if (builtin_program.core_bpf_migration_config) |core_bpf_config| {
            if (new_feature_activations.contains(core_bpf_config.enable_feature_id)) {
                if (true) @panic("not expected by fuzz harness");
                migrateBuiltinProgramToCoreBpf() catch |err| {
                    std.debug.print("Failed to migrate builtin program {} to Core BPF: {}\n", .{ builtin_program.program_id, err });
                    return err;
                };
                is_core_bpf = true;
            } else {
                const maybe_account = try tryGetAccount(accounts_db, builtin_program.program_id);
                is_core_bpf = if (maybe_account) |account|
                    account.owner.equals(&program.bpf_loader.v3.ID)
                else
                    false;
            }
        }

        if (builtin_program.enable_feature_id) |enable_feature_id| {
            const should_enable_on_transition = !is_core_bpf and if (allow_new_activations)
                new_feature_activations.contains(enable_feature_id)
            else
                feature_set.active.contains(enable_feature_id);

            if (should_enable_on_transition) {
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
        }
    }

    for (builtins.STATELESS_BUILTINS) |builtin_program| {
        const core_bpf_config = builtin_program.core_bpf_migration_config orelse continue;
        if (new_feature_activations.contains(core_bpf_config.enable_feature_id)) {
            migrateBuiltinProgramToCoreBpf() catch |err| {
                std.debug.print("Failed to migrate stateless builtin program {} to Core BPF: {}\n", .{ builtin_program.program_id, err });
                return err;
            };
        }
    }

    for (program.precompiles.PRECOMPILES) |precompile| {
        const feature_id = precompile.required_feature orelse continue;
        if (!feature_set.active.contains(feature_id)) continue;

        try accounts_db.putAccount(
            slot,
            precompile.program_id,
            .{
                .lamports = 1,
                .data = &.{},
                .executable = true,
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                .rent_epoch = 0,
            },
        );
    }
}

fn migrateBuiltinProgramToCoreBpf() !void {
    @panic("Unimplemented: migrateBuiltinProgramToCoreBpf");
}

fn computeActiveFeatureSet(
    allocator: Allocator,
    slot: u64,
    feature_set: *FeatureSet,
    accounts_db: *AccountsDb,
    allow_new_activations: bool,
) !std.AutoArrayHashMapUnmanaged(Pubkey, void) {
    // TODO: requires reimplementation of feature_set.inactive or some other solution
    // var inactive = std.AutoArrayHashMapUnmanaged(Pubkey, void){};
    var pending = std.AutoArrayHashMapUnmanaged(Pubkey, void){};
    errdefer pending.deinit(allocator);

    const keys = try allocator.dupe(Pubkey, feature_set.active.keys());
    defer allocator.free(keys);

    for (feature_set.active.keys()) |feature_id| {
        var maybe_activation_slot: ?u64 = null;

        if (try tryGetAccount(accounts_db, feature_id)) |account| {
            if (try featureActivationSlotFromAccount(
                allocator,
                account,
            )) |activation_slot| {
                maybe_activation_slot = activation_slot;
            } else if (allow_new_activations) {
                try pending.put(allocator, feature_id, {});
                maybe_activation_slot = slot;
            }
        }

        if (maybe_activation_slot) |activation_slot| {
            try feature_set.active.put(allocator, feature_id, activation_slot);
        } else {
            // try inactive.put(allocator, feature_id, {});
        }
    }

    return pending;
}

fn featureActivationSlotFromAccount(allocator: Allocator, account: Account) !?u64 {
    if (!account.owner.equals(&sig.runtime.ids.FEATURE_PROGRAM_ID)) return null;
    const data_len = account.data.len();
    const data = try allocator.alloc(u8, data_len);
    errdefer allocator.free(data);
    account.data.readAll(data);
    return bincode.readFromSlice(failing_allocator, ?u64, data, .{});
}

fn tryGetAccount(
    accounts_db: *AccountsDb,
    pubkey: Pubkey,
) !?Account {
    const maybe_account = accounts_db.getAccount(&pubkey) catch |err| switch (err) {
        error.PubkeyNotInIndex => null,
        error.SlotNotFound => null,
        error.OutOfMemory => return error.OutOfMemory,
        error.FileIdNotFound => return error.FileIdNotFound,
        error.InvalidOffset => return error.InvalidOffset,
    };
    if (maybe_account) |account| {
        return account;
    }
    return null;
}

fn accountSharedDataFromAccount(
    allocator: Allocator,
    account: *const Account,
) !AccountSharedData {
    const data = try account.data.dupeAllocatedOwned(allocator);
    defer data.deinit(allocator);

    return .{
        .lamports = account.lamports,
        .data = try allocator.dupe(u8, data.owned_allocation),
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
    };
}
