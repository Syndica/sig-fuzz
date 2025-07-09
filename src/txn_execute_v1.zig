const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");

const EMIT_LOGS = false;

/// [fd] https://github.com/firedancer-io/firedancer/blob/61e3d2e21419fc71002aa1c037ab637cea85416d/src/flamenco/runtime/tests/harness/fd_exec_sol_compat.c#L583
/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/7d039a85e55227fdd7ae5c9d0e1c36c7cf5b01f5/src/txn_fuzzer.rs#L46
export fn sol_compat_txn_execute_v1(
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
    var pb_txn_ctx = pb.TxnContext.decode(
        in_slice,
        decode_arena.allocator(),
    ) catch |err| {
        std.debug.print("pb.TxnContext.decode: {s}\n", .{@errorName(err)});
        return 0;
    };
    defer pb_txn_ctx.deinit();

    const result = executeTxnContext(allocator, pb_txn_ctx, EMIT_LOGS) catch |err| {
        std.debug.print("executeTxnContext: {s}\n", .{@errorName(err)});
        return 0;
    };

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

const builtins = @import("builtins.zig");

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
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const Slot = sig.core.Slot;
const Signature = sig.core.Signature;
const StatusCache = sig.core.StatusCache;
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

const loadTestAccountsDB = sig.accounts_db.db.loadTestAccountsDBSigFuzz;
const fillMissingSysvarCacheEntries = sig.replay.update_sysvar.fillMissingEntries;
const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;

fn executeTxnContext(allocator: std.mem.Allocator, pb_txn_ctx: pb.TxnContext, emit_logs: bool) !pb.TxnResult {
    errdefer |err| {
        std.debug.print("executeTxnContext: {s}\n", .{@errorName(err)});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }

    // Load info from the protobuf transaction context
    const feature_set = try loadFeatureSet(allocator, &pb_txn_ctx);
    defer feature_set.deinit(allocator);

    const blockhashes = try loadBlockhashes(allocator, &pb_txn_ctx);
    defer allocator.free(blockhashes);

    // const transaction = try loadTransaction(allocator, &pb_txn_ctx);
    // defer transaction.deinit(allocator);

    var accounts_map = try loadAccountsMap(allocator, &pb_txn_ctx);
    defer deinitMapAndValues(allocator, accounts_map);

    var builtin_accounts_map = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData){};
    defer deinitMapAndValues(allocator, builtin_accounts_map);

    // TODO: use??
    // const fee_collector = Pubkey.parseBase58String("1111111111111111111111111111111111") catch unreachable;

    // Load genesis config
    var genesis_config = GenesisConfig.default(allocator);
    defer genesis_config.deinit(allocator);
    genesis_config.epoch_schedule = getSysvarFromAccounts(
        allocator,
        EpochSchedule,
        &accounts_map,
    ) orelse EpochSchedule.DEFAULT;
    genesis_config.rent = getSysvarFromAccounts(
        allocator,
        Rent,
        &accounts_map,
    ) orelse Rent.DEFAULT;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    var accounts_db = try loadTestAccountsDB(
        allocator,
        false,
        .noop,
        tmp_dir_root.dir,
    );
    defer accounts_db.deinit();

    var epoch: Epoch = undefined;
    var epoch_schedule: EpochSchedule = undefined;

    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);

    var compute_budget = ComputeBudget.DEFAULT;
    compute_budget.compute_unit_limit = compute_budget.compute_unit_limit;

    var fee_rate_govenor = FeeRateGovernor.DEFAULT;

    var blockhash_queue = BlockhashQueue.DEFAULT;
    defer blockhash_queue.deinit(allocator);

    var epoch_stakes = EpochStakesMap{};
    defer epoch_stakes.deinit(allocator);

    var sysvar_cache = SysvarCache{};
    defer sysvar_cache.deinit(allocator);

    var vm_environment = vm.Environment{};
    defer vm_environment.deinit(allocator);

    // Bank::new_with_paths(...)
    {
        epoch = 0;
        try ancestors.addSlot(allocator, 0);
        // bank.compute_budget = runtime_config.compute_budget;
        // bank.transaction_account_lock_limit = null;
        // bank.transaction_debug_keys = null;
        // bank.cluster_type = genesis_config.cluster_type;
        // bank.feature_set = feature_set;

        // Bank::process_genesis_config(...)
        {
            // Set the feee rate governor
            fee_rate_govenor = genesis_config.fee_rate_governor;

            // Insert genesis config accounts
            std.debug.assert(genesis_config.accounts.count() == 0);

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

        // Bank::finish_init(...)
        {
            // Set reward pool pubkeys
            std.debug.assert(genesis_config.rewards_pools.count() == 0);

            // TODO: apply feature activations
            std.debug.print("WARNING: applyFeatureActivations not implemented\n", .{});

            // Set limits for 50m block limits
            if (feature_set.active.contains(features.RAISE_BLOCK_LIMITS_TO_50M)) {
                @panic("set limits not implemented");
            }

            // Set limits for 60m block limits
            if (feature_set.active.contains(features.RAISE_BLOCK_LIMITS_TO_60M)) {
                @panic("set limits not implemented");
            }

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
                if (builtin_program.enable_feature_id != null) continue;
                try builtin_accounts_map.put(allocator, builtin_program.program_id, .{
                    .lamports = 1,
                    .data = try allocator.dupe(u8, builtin_program.data),
                    .executable = true,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                    .rent_epoch = 0,
                });
            }

            // Add precompiles
            for (program.precompiles.PRECOMPILES) |precompile| {
                if (precompile.required_feature != null) continue;
                try builtin_accounts_map.put(allocator, precompile.program_id, .{
                    .lamports = 1,
                    .data = try allocator.dupe(u8, &.{}),
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

        // Add epoch stakes for all epochs up to the banks slot using banks stakes cache
        // The bank slot is 0 and stakes cache is empty, so we add default epoch stakes.
        for (0..epoch_schedule.getLeaderScheduleEpoch(0)) |e| {
            try epoch_stakes.put(allocator, e, EpochStakes.DEFAULT);
        }

        // TODO: updateStakeHistory(None)
        // TODO: updateClock(None)
        // TODO: updateRent();
        // TODO: updateEpochSchedule();
        // TODO: updateRecentBlockhashes();
        // TODO: updateLastRestartSlot();
        // TODO: fillMissingSysvarCacheEntries();
    }

    // NOTE: The following logic should not impact txn fuzzing
    // let bank_forks = BankForks::new_rw_arc(bank);
    //     Sets the fork graph in the banks program cache to the newly created bank_forks.
    //     bank.set_fork_graph_in_program_cache(Arc::downgrade(&bank_forks));
    // let mut bank = bank_forks.read().unwrap().root_bank();
    //     Just gets the root bank
    // bank.rehash();
    //     Hashes the bank state, should be irrelevant for txn fuzzing

    const slot = loadSlot(&pb_txn_ctx);
    if (slot > 0) {
        // Bank::new_from_parent(...)
        {
            // Clone epoch schedule
            // epoch_schedule = epoch_schedule;

            // Get epoch
            epoch = epoch_schedule.getEpoch(slot);

            // Clone accounts db
            // let (rc, bank_rc_creation_time_us) = measure_us!({
            //     let accounts_db = Arc::clone(&parent.rc.accounts.accounts_db);
            //     BankRc {
            //         accounts: Arc::new(Accounts::new(accounts_db)),
            //         parent: RwLock::new(Some(Arc::clone(&parent))),
            //         bank_id_generator: Arc::clone(&parent.rc.bank_id_generator),
            //     }
            // });

            // Clone status_cache
            // const status_cache = parent.status_cache.clone();

            // Derive new fee rate governor
            fee_rate_govenor = FeeRateGovernor.initDerived(
                &fee_rate_govenor,
                0, // parent.signature_count()
            );

            // Get bank id
            // let bank_id = rc.bank_id_generator.fetch_add(1, Relaxed) + 1;

            // Clone blockhash queue
            // blockhash_queue = blockhash_queue;

            // Clone stakes cache
            // const stakes_cache = parent.stakes_cache.clone();

            // Clone epoch stakes
            // epoch_stakes = epoch_stakes;

            // Create new transaction processor
            // const transaction_processor = TransactionBatchProcessor::new_from(&parent.transaction_processor, slot, epoch);
            {
                sysvar_cache.reset(allocator);
            }

            // Clone rewards pool pubkeys
            // const rewards_pools = parent.rewards_pools.clone();

            // Clone transaction debug keys
            // const transaction_debug_keys = parent.transaction_debug_keys.clone();

            // Clone transaction log collector config
            // const transaction_log_collector_config = parent.transaction_log_collector_config.clone();

            // Clone feature set
            // feature_set = feature_set;

            // Get initial accounts data size
            // const initial_accounts_data_size = parent.load_accounts_data_size();

            // Init new bank -- lots of copying of fields here
            // var new = Bank{...}

            // Create ancestors with new slot and all parent slots
            try ancestors.addSlot(allocator, slot);

            // Process new epoch (if we are here we know that the parent epoch is 0 in the txn fuzzing context
            // otherwise we would check if the new epoch is greater than the parent epoch)
            // Bank::process_new_epoch(...)
            {}

            // Distrubute partitioned epoch rewards
            // new.distribute_partitioned_epoch_rewards(...)
            {}

            // Prepare program cache for upcoming feature set
            {}

            // Update sysvars
            {
                // TODO: updateSlotHashes();
                // TODO: updateStakeHistory(parent.epoch);
                // TODO: updateClock(parent.epoch);
                // TODO: updateLastRestartSlot();
            }

            // Fill missing sysvar cache entries
            try fillMissingSysvarCacheEntries(allocator, &accounts_db, &ancestors, &sysvar_cache);

            // Get num accounts modified by this slot if accounts lt hash enabled
            {}

            // A bunch of stats stuff...
        }

        // bank = bank_forks.write().unwrap().insert(bank).clone_without_scheduler();
        {
            // if (root < highest_slot_at_startup) {
            //     bank.check_program_modification_slot = true;
            // }

            // bunch of scheduler and forks stuff...
        }

        // ProgramCache::prune(slot, epoch)
        {}
    }

    // NOTE: At this point we can write all the builtin accounts to accountsdb at slot 0
    {
        var pubkeys = std.ArrayListUnmanaged(Pubkey){};
        defer pubkeys.deinit(allocator);
        var accounts = std.ArrayListUnmanaged(Account){};
        defer {
            for (accounts.items) |acc| acc.deinit(allocator);
            accounts.deinit(allocator);
        }

        for (builtin_accounts_map.keys(), builtin_accounts_map.values()) |pubkey, account| {
            try pubkeys.append(allocator, pubkey);
            try accounts.append(allocator, .{
                .lamports = account.lamports,
                .data = .initAllocatedOwned(try allocator.dupe(u8, account.data)),
                .owner = account.owner,
                .executable = account.executable,
                .rent_epoch = account.rent_epoch,
            });
        }

        std.debug.print("Putting {} accounts into accounts db at slot {}\n", .{
            accounts.items.len,
            0,
        });
        try accounts_db.putAccountSlice(
            accounts.items,
            pubkeys.items,
            0,
        );
    }

    // Load accounts into accounts db
    {
        var pubkeys = std.ArrayListUnmanaged(Pubkey){};
        defer pubkeys.deinit(allocator);
        var accounts = std.ArrayListUnmanaged(Account){};
        defer {
            for (accounts.items) |acc| acc.deinit(allocator);
            accounts.deinit(allocator);
        }

        for (accounts_map.keys(), accounts_map.values()) |pubkey, account| {
            try pubkeys.append(allocator, pubkey);
            try accounts.append(allocator, .{
                .lamports = account.lamports,
                .data = .initAllocatedOwned(try allocator.dupe(u8, account.data)),
                .owner = account.owner,
                .executable = account.executable,
                .rent_epoch = account.rent_epoch,
            });
        }

        std.debug.print("Putting {} accounts into accounts db at slot {}\n", .{
            accounts.items.len,
            slot,
        });
        try accounts_db.putAccountSlice(accounts.items, pubkeys.items, slot);
    }

    // Reset and fill sysvar cache
    sysvar_cache.reset(allocator);
    try fillMissingSysvarCacheEntries(allocator, &accounts_db, &ancestors, &sysvar_cache);

    // Update epoch schedule and rent to minimum rent exempt balance
    // TODO: updateEpochSchedule();
    // TODO: updateRent();

    // Get lamports per signature from first entry in recent blockhashes
    const lamports_per_signature = blk: {
        const recent_blockhashes = sysvar_cache.get(RecentBlockhashes) catch
            break :blk null;

        const first_entry = recent_blockhashes.getFirst() orelse
            break :blk null;

        break :blk if (first_entry.lamports_per_signature != 0)
            first_entry.lamports_per_signature
        else
            null;
    } orelse fee_rate_govenor.lamports_per_signature;

    // Register blockhashes
    for (blockhashes) |blockhash| {
        try blockhash_queue.insertHash(allocator, blockhash, lamports_per_signature);
    }

    // Update recent blockhashes
    // TODO: updateRecentBlockhashes();

    // Reset and fill sysvar cache
    sysvar_cache.reset(allocator);
    try fillMissingSysvarCacheEntries(allocator, &accounts_db, &ancestors, &sysvar_cache);

    _ = emit_logs;

    return .{};
}

fn parseHash(bytes: []const u8) !Hash {
    if (bytes.len != Hash.SIZE) return error.OutOfBoundsHash;
    return .{ .data = bytes[0..Hash.SIZE].* };
}

fn parsePubkey(bytes: []const u8) !Pubkey {
    if (bytes.len != Pubkey.SIZE) return error.OutOfBoundsPubkey;
    return .{ .data = bytes[0..Pubkey.SIZE].* };
}

fn loadSlot(pb_txn_ctx: *const pb.TxnContext) u64 {
    return if (pb_txn_ctx.slot_ctx) |ctx| ctx.slot else 10;
}

fn loadFeatureSet(allocator: std.mem.Allocator, pb_txn_ctx: *const pb.TxnContext) !FeatureSet {
    var feature_set = blk: {
        const maybe_pb_features = if (pb_txn_ctx.epoch_ctx) |epoch_ctx|
            if (epoch_ctx.features) |pb_features| pb_features else null
        else
            null;

        const pb_features = maybe_pb_features orelse break :blk FeatureSet.EMPTY;

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

        break :blk feature_set;
    };

    if (try std.process.hasEnvVar(allocator, "TOGGLE_DIRECT_MAPPING")) {
        if (feature_set.active.contains(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING)) {
            _ = feature_set.active.swapRemove(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING);
        } else {
            try feature_set.active.put(allocator, features.BPF_ACCOUNT_DATA_DIRECT_MAPPING, 0);
        }
    }

    return feature_set;
}

/// Load blockhashes from the protobuf transaction context.
/// If no blockhashes are provided, a default blockhash of zeroes is returned.
fn loadBlockhashes(
    allocator: std.mem.Allocator,
    pb_txn_ctx: *const pb.TxnContext,
) ![]Hash {
    const pb_blockhashes = pb_txn_ctx.blockhash_queue.items;
    if (pb_blockhashes.len == 0)
        return try allocator.dupe(Hash, &.{Hash.ZEROES});

    const blockhashes = try allocator.alloc(Hash, pb_blockhashes.len);
    errdefer allocator.free(blockhashes);

    for (blockhashes, pb_blockhashes) |*blockhash, pb_blockhash|
        blockhash.* = try parseHash(pb_blockhash.getSlice());

    return blockhashes;
}

/// Load all accounts from the protobuf transaction context.
fn loadAccountsMap(
    allocator: std.mem.Allocator,
    pb_txn_ctx: *const pb.TxnContext,
) !std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData) {
    const pb_accounts = pb_txn_ctx.account_shared_data.items;

    var accounts = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData){};
    errdefer deinitMapAndValues(allocator, accounts);

    for (pb_accounts) |pb_account| {
        try accounts.put(allocator, try parsePubkey(pb_account.address.getSlice()), .{
            .lamports = pb_account.lamports,
            .data = try allocator.dupe(u8, pb_account.data.getSlice()),
            .owner = try parsePubkey(pb_account.owner.getSlice()),
            .executable = pb_account.executable,
            .rent_epoch = pb_account.rent_epoch,
        });
    }

    return accounts;
}

/// Load the transaction from the protobuf transaction context.
/// If no transaction is provided, an error is returned.
fn loadTransaction(
    allocator: std.mem.Allocator,
    pb_txn_ctx: *const pb.TxnContext,
) !Transaction {
    const pb_txn = pb_txn_ctx.tx orelse return error.NoTransaction;

    const signatures = try allocator.alloc(
        Signature,
        @max(pb_txn.signatures.items.len, 1),
    );

    for (pb_txn.signatures.items, 0..) |pb_signature, i|
        signatures[i] = .{ .data = pb_signature.getSlice()[0..Signature.SIZE].* };

    if (pb_txn.signatures.items.len == 0)
        signatures[0] = Signature.ZEROES;

    const version, const message = try loadTransactionMesssage(
        allocator,
        pb_txn.message.?,
    );

    return .{
        .signatures = signatures,
        .version = version,
        .msg = message,
    };
}

/// Load the transaction version and message from the protobuf transaction message.
fn loadTransactionMesssage(
    allocator: std.mem.Allocator,
    message: pb.TransactionMessage,
) !struct { TransactionVersion, TransactionMessage } {
    const account_keys = try allocator.alloc(Pubkey, message.account_keys.items.len);
    for (account_keys, message.account_keys.items) |*account_key, pb_account_key|
        account_key.* = .{ .data = pb_account_key.getSlice()[0..Pubkey.SIZE].* };

    const recent_blockhash = Hash{ .data = message.recent_blockhash.getSlice()[0..Hash.SIZE].* };

    const instructions = try allocator.alloc(
        TransactionInstruction,
        message.instructions.items.len,
    );
    for (instructions, message.instructions.items) |*instruction, pb_instruction| {
        const account_indexes = try allocator.alloc(u8, pb_instruction.accounts.items.len);
        for (account_indexes, pb_instruction.accounts.items) |*account_index, pb_account_index|
            account_index.* = @truncate(pb_account_index);
        instruction.* = .{
            .program_index = @truncate(pb_instruction.program_id_index),
            .account_indexes = account_indexes,
            .data = try allocator.dupe(u8, pb_instruction.data.getSlice()),
        };
    }

    const address_lookups = try allocator.alloc(
        TransactionAddressLookup,
        message.address_table_lookups.items.len,
    );
    for (address_lookups, message.address_table_lookups.items) |*lookup, pb_lookup| {
        const writable_indexes = try allocator.alloc(u8, pb_lookup.writable_indexes.items.len);
        for (writable_indexes, pb_lookup.writable_indexes.items) |*writable_index, pb_writable_index|
            writable_index.* = @truncate(pb_writable_index);

        const readonly_indexes = try allocator.alloc(u8, pb_lookup.readonly_indexes.items.len);
        for (readonly_indexes, pb_lookup.readonly_indexes.items) |*readonly_index, pb_readonly_index|
            readonly_index.* = @truncate(pb_readonly_index);

        lookup.* = TransactionAddressLookup{
            .table_address = Pubkey{ .data = pb_lookup.account_key.getSlice()[0..Pubkey.SIZE].* },
            .writable_indexes = writable_indexes,
            .readonly_indexes = readonly_indexes,
        };
    }

    const header = message.header orelse pb.MessageHeader{
        .num_required_signatures = 1,
        .num_readonly_signed_accounts = 0,
        .num_readonly_unsigned_accounts = 0,
    };

    return .{
        if (message.is_legacy)
            .legacy
        else
            .v0,
        .{
            .signature_count = @truncate(@max(1, header.num_required_signatures)),
            .readonly_signed_count = @truncate(header.num_readonly_signed_accounts),
            .readonly_unsigned_count = @truncate(header.num_readonly_unsigned_accounts),
            .account_keys = account_keys,
            .recent_blockhash = recent_blockhash,
            .instructions = instructions,
            .address_lookups = address_lookups,
        },
    };
}

/// Load a sysvar from the accounts map.
/// If the sysvar is not present or has zero lamports, return null.
pub fn getSysvarFromAccounts(
    allocator: std.mem.Allocator,
    comptime T: type,
    accounts: *const std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
) ?T {
    const account = accounts.getPtr(T.ID) orelse return null;
    if (account.lamports == 0) return null;
    return sig.bincode.readFromSlice(
        allocator,
        T,
        account.data,
        .{},
    ) catch null;
}

// pub fn initAccountsDb(
//     allocator: std.mem.Allocator,
//     pb_txn_ctx: *const pb.TxnContext,
// ) !AccountsDb {
//     var hasher = std.crypto.hash.Blake3.init(.{});
//     const bytes: []const u8 = @as([*]const u8, @ptrCast(&pb_txn_ctx))[0..@sizeOf(pb.TxnContext)];
//     hasher.update(bytes);
//     var seed = Hash.ZEROES;
//     hasher.final(&seed.data);
//     var prng = std.Random.DefaultPrng.init(std.mem.bytesAsValue(u64, seed.data[0..8]).*);

//     const snapshot_dir_name = try std.fmt.allocPrint(
//         allocator,
//         "snapshot-dir-{}",
//         .{prng.random().int(u64)},
//     );
//     defer allocator.free(snapshot_dir_name);
//     try std.fs.cwd().makeDir(snapshot_dir_name);
//     defer std.fs.cwd().deleteTree(snapshot_dir_name) catch {};
//     const snapshot_dir = try std.fs.cwd().openDir(
//         snapshot_dir_name,
//         .{ .iterate = true },
//     );

//     return try sig.accounts_db.AccountsDB.init(.{
//         .allocator = allocator,
//         .logger = .noop,
//         .snapshot_dir = snapshot_dir,
//         .geyser_writer = null,
//         .gossip_view = null,
//         .index_allocation = .ram,
//         .number_of_index_shards = 1,
//         .buffer_pool_frames = 1024,
//     });
// }

test "execute sample txn context" {
    const allocator = std.testing.allocator;
    const pb_txn_ctx = try sampleTxnContext(allocator);
    defer pb_txn_ctx.deinit();

    const result = executeTxnContext(allocator, pb_txn_ctx, false) catch |err| {
        std.debug.print("executeTxnContext failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer result.deinit();
}

/// 0-sample.txt
/// 0a73c09ab08f77e00b0faa8cf0d70408113b0a92_265678.fix
fn sampleTxnContext(allocator: std.mem.Allocator) !pb.TxnContext {
    @setEvalBranchQuota(1_000_000);

    const ManagedString = @import("protobuf").ManagedString;
    const pb_slot: u64 = 963106073;

    var pb_blockhashes = std.ArrayList(ManagedString).init(allocator);
    try pb_blockhashes.appendSlice(&.{
        .static(&(Hash.parseBase58String("Brqgfg9qhuU6BN29JvA1U2yUwd89evLxkGrPhgQ9T7GK") catch unreachable).data),
        .static(&(Hash.parseBase58String("81T56cg6QzEjVM86Rroy5FCxFf6pwuXnj7DYXNeHNYP") catch unreachable).data),
        .static(&(Hash.parseBase58String("36nEg9eQu2k9ZbjjgUN4wbsc7n5mNj6TbzXkUznJJ22B") catch unreachable).data),
        .static(&(Hash.parseBase58String("GdWCqpD7scfusjv2XR5zGc72eN4WV3uJU9qqocPdz1Qb") catch unreachable).data),
        .static(&(Hash.parseBase58String("VA51KKvmkQNuTVMn6i9K7Q3aZPx3Zc1DzTQdbBLrLWj") catch unreachable).data),
        .static(&(Hash.parseBase58String("5kYLD3hcUBL119NCHvzxPLpB9AQRLCcvRdnh8LKmg1Ry") catch unreachable).data),
        .static(&(Hash.parseBase58String("EYVsXqunwUb3F86SoX4FF7iySFtAJSdLKG7FgMtf3jcT") catch unreachable).data),
        .static(&(Hash.parseBase58String("Fv2sZfGeyMMTQJ4d4qTncp3WcC38P2AoRVBJsgVp8WCf") catch unreachable).data),
        .static(&(Hash.parseBase58String("FPYkMwSAs6trDDL43XVm9M33KKkZ9TEvy8EarAcrPetX") catch unreachable).data),
        .static(&(Hash.parseBase58String("BfctqhCvJMMra4yU9bZhfk4WX6WgPHkrVxhqedrKQmJX") catch unreachable).data),
        .static(&(Hash.parseBase58String("ABZVpG53wJbQFy4KSdZRcaaQJXmRr7tXyo5LkDcYCEmm") catch unreachable).data),
        .static(&(Hash.parseBase58String("BLWf8LmnMxRAv5w3RJ5mtGBmjcHbDBhGDqj5rVQgCZGK") catch unreachable).data),
        .static(&(Hash.parseBase58String("Eh15BA5rcEpy1urEVy6dHn1tiZ9wfet8nkM6CMqmacWT") catch unreachable).data),
        .static(&(Hash.parseBase58String("EBfwhNr2qbhH2o1DRi4irs4fjhLEfMBfzYPbT2CBkjjV") catch unreachable).data),
        .static(&(Hash.parseBase58String("DuhSdTShpk6XvCW79xXpBHcH9cEmRyktA9HcW38ivQ3R") catch unreachable).data),
        .static(&(Hash.parseBase58String("CwNh2tU6oMYJkjo3VnSTyyr9sYY9mQpPr7eEuBqdDevj") catch unreachable).data),
        .static(&(Hash.parseBase58String("G2oUYokQXJBrALkpzjC2EnoV1cdKZnBVFYrWX1KWC1Ao") catch unreachable).data),
        .static(&(Hash.parseBase58String("581v5cqFQ1UL65hKQPT3DEdzRDCG17ak41JWrceo7wdH") catch unreachable).data),
        .static(&(Hash.parseBase58String("3LwXEdtyWt2GVYoWhPbh2rd9PcZEfYafdAXW874f5rUX") catch unreachable).data),
        .static(&(Hash.parseBase58String("Edo3wzDCbjhXSwXJdMm23LwACZBQxGmUtfh4j2ChYBYT") catch unreachable).data),
        .static(&(Hash.parseBase58String("FWPXjkD2CsfnXpRyHzFJXhPDY4MwDMaKjom5LLA9rMmq") catch unreachable).data),
        .static(&(Hash.parseBase58String("BGnbTWMweP3or8s681itz65bi1ocab1A8xBC9W24gUcX") catch unreachable).data),
        .static(&(Hash.parseBase58String("3bg4rkFGEYp6ZnmKzPBcgVZZWbxE3igFjZUZAYx2Ddwd") catch unreachable).data),
        .static(&(Hash.parseBase58String("FP7DFB97czLG5tEzCvFfq8ryn4NNCeJ22sArYP65Qi6b") catch unreachable).data),
        .static(&(Hash.parseBase58String("Bb5bNagXPrhZkNyZc4mNauxwfQtEqLZkXdVSKXzcvJEK") catch unreachable).data),
        .static(&(Hash.parseBase58String("5GSV45miWUYEoaHoRqsZPUBpWuHBNvX21JdaK9hhp34s") catch unreachable).data),
        .static(&(Hash.parseBase58String("4R812se79V9g3iSCcThn6MmPKN1udJvXRiUxof3JZbiX") catch unreachable).data),
        .static(&(Hash.parseBase58String("6VemdQJRFejPim7gKDU69DX45GgeBkj892RHiF1g3VL3") catch unreachable).data),
        .static(&(Hash.parseBase58String("8GE5FQkL1Txpzr6QoAg8BFBujBh9KYp6EDF58AMPc8XZ") catch unreachable).data),
        .static(&(Hash.parseBase58String("4rmm9NdRofCaUbqyMgWxpuTU5gEdC9D3dTB1NdSP8qxs") catch unreachable).data),
        .static(&(Hash.parseBase58String("EJkfUHsJZ8zigLy2AsEQdEWnw57oQ3ixQvFhoYeyDfBd") catch unreachable).data),
        .static(&(Hash.parseBase58String("AeBDhZhRN3GiiqPCudr5gcyPnc6ob1yqrfFNfMMyncA3") catch unreachable).data),
        .static(&(Hash.parseBase58String("HSbi9SZgihFPYnQUZnGzbvShMUwupcnevR76gb6vNQPH") catch unreachable).data),
        .static(&(Hash.parseBase58String("9VpyR32aG5w2r5v4c7cHmfJ3YrhxWuibLr52TP9evG4X") catch unreachable).data),
        .static(&(Hash.parseBase58String("HnRisD9hpCmxxWBXZzWkTXi9kFdkSNqDjD9uZ8wFHKom") catch unreachable).data),
        .static(&(Hash.parseBase58String("B1LaeYgZ5noLns3ScfTf6rV8MjB5PRj1iMybAGitvoAf") catch unreachable).data),
        .static(&(Hash.parseBase58String("7LshGoCmGZsZTZnTQd5eieiBZaEMWedbSQ9p9Bp4HmUb") catch unreachable).data),
        .static(&(Hash.parseBase58String("3YPTnKcKPNCC6yEfv4FnMDFCg8m7KAfP5w6sQwzLusY3") catch unreachable).data),
        .static(&(Hash.parseBase58String("41QJqQc9DruQ16nhUe3jSNHY84e2sfUHXvdcTrPsgZKu") catch unreachable).data),
        .static(&(Hash.parseBase58String("7ngFGiJfPugBrJbJGK7iYZQnVAjG1wFWgK8gWjegvKaf") catch unreachable).data),
        .static(&(Hash.parseBase58String("9yRBLtRJ8qgRKw9GwsCX2SAt3eiGRUWSe2zQ437BB9JP") catch unreachable).data),
        .static(&(Hash.parseBase58String("2bZTtX1L5xyjx8fUiNZ4r3Riz7aNgTaJ61Unw31VGB11") catch unreachable).data),
        .static(&(Hash.parseBase58String("3ZudUZTm9uhcnYG8rtgnecEKNAQUVxwNREKP9oFUTyYT") catch unreachable).data),
        .static(&(Hash.parseBase58String("2oVRwpRQKs5GC2oX6FEJH5qvxDKojABMm5BQ1rTxkswM") catch unreachable).data),
        .static(&(Hash.parseBase58String("6pmRPTGhKZ4WGfx39PEebgnkBwGsYRnTtfgUxzEa3ar3") catch unreachable).data),
        .static(&(Hash.parseBase58String("8DrZjLWMj6UfwEMsRfTKEGYzXtM3NiCYXkBvMWEDKgW3") catch unreachable).data),
        .static(&(Hash.parseBase58String("D5g22TZ4zeJGYRXhDREvqHWsCPascvLBuUamspjZTbUB") catch unreachable).data),
        .static(&(Hash.parseBase58String("J2AHpfNSJj7zbPsDQa5Xs6tosfdCq4UtDFHdb9hY5fqy") catch unreachable).data),
        .static(&(Hash.parseBase58String("EooYQHcHH3e8ztqqggP1KPtvwNSK56NJte2eb8sSAS3H") catch unreachable).data),
        .static(&(Hash.parseBase58String("3KQYijRRysiEULupdQzbe8z6VTcsA9igjmn12hh7Bocj") catch unreachable).data),
        .static(&(Hash.parseBase58String("ECjT1A5yqFWJBF8piU3Fg68yCQXghSxCf8bHFRzB3Uxo") catch unreachable).data),
        .static(&(Hash.parseBase58String("xSa7rvJwRQDFHB24QkDvyHq8oUNDGgN8KXh1RYKjjmH") catch unreachable).data),
        .static(&(Hash.parseBase58String("52FANf9qLdyTBRbApgqcVy29w1UHVtcddXwbGGmKdTg3") catch unreachable).data),
        .static(&(Hash.parseBase58String("CcTZTTgCMmZzD3p1UsF83A9wWKURqeD1KXhyLp88XFZ9") catch unreachable).data),
        .static(&(Hash.parseBase58String("G6kCTjN8bMZEjHMu8ZcD1QTRZiRbtDJGREBBxgEr6YQw") catch unreachable).data),
        .static(&(Hash.parseBase58String("wxEkJSDy4tWVnyBSN3ZhTnjDAzLqX5acMRMHpDPR3Qb") catch unreachable).data),
        .static(&(Hash.parseBase58String("8RBNfhJp5Wx3kbJgQVs77DXtxRGLAAyLQ94JAeqvPnAb") catch unreachable).data),
        .static(&(Hash.parseBase58String("HeyxuA8nG6eBQZck7nYCGjwx44ygaGXKYsgdoZFfX9A7") catch unreachable).data),
        .static(&(Hash.parseBase58String("5NLCrsx8TDiBXdFkMVwtkJHuEnmFxgQBLTsE8ofhfpn3") catch unreachable).data),
        .static(&(Hash.parseBase58String("7SfN8q1Le7TS5NnAdrbdMFYRTc9uk4zRqkNe2mZBZ7PD") catch unreachable).data),
        .static(&(Hash.parseBase58String("Da6BCVUApgNwmUqQvjKjDiZYseJGMpF1khPhg9JUR2ZD") catch unreachable).data),
        .static(&(Hash.parseBase58String("BDvj4GQPg2vRhvZo3oLBK9c2At4LfpQHZXcwTspEwcc7") catch unreachable).data),
        .static(&(Hash.parseBase58String("FCnPbNQredzSapocfzP27gBpGDv6LyLuB5aVDn53q32X") catch unreachable).data),
        .static(&(Hash.parseBase58String("DxE3FFxJgLsiMoSfkC3oGthXtpWoBix3J1zR7e2o9Zsm") catch unreachable).data),
        .static(&(Hash.parseBase58String("6xjFToNyoxYmqz77qwkL9FuKToCEGNEx5kYEV9jz6ArB") catch unreachable).data),
        .static(&(Hash.parseBase58String("AZ9roNkb7sNsBwqR4K23ThpUkxfKTiNbsgVKMQUb4EqM") catch unreachable).data),
        .static(&(Hash.parseBase58String("HCGY3iQG97de8nMV7Ze73hJUN61mdVj1CGRzF8WNc6jZ") catch unreachable).data),
        .static(&(Hash.parseBase58String("EV8xB5xRaf9v5sH5QwcDVizSyCJ37PaZk6d4u8iPWpPZ") catch unreachable).data),
        .static(&(Hash.parseBase58String("ZLzn5CxbJugfmgbEvPZC8CfmQihBjCxVjZgfd4yWD2o") catch unreachable).data),
        .static(&(Hash.parseBase58String("An7jDtCRZRt9R9dCRwoeTSiCjSgBjKG7R1MQA2rZYu35") catch unreachable).data),
        .static(&(Hash.parseBase58String("22STPnpwsScA24QTuAk6iYEVHDJ3cJgYgMaEjskiL8hD") catch unreachable).data),
        .static(&(Hash.parseBase58String("HFseWh7pnfJBy81osSULnRbUHbYRL2KFeq27VWTz9XVZ") catch unreachable).data),
        .static(&(Hash.parseBase58String("DuYWx9awumJrujFugTyZForYbv9k2ABXvteDSvcS98Go") catch unreachable).data),
        .static(&(Hash.parseBase58String("8g8CNKiVzg9jxU22AXRz2qhqDtncPWLTG3zLU3wdMMEX") catch unreachable).data),
        .static(&(Hash.parseBase58String("xU7LRbwMWDHubdRFfoc5Z4eNZDxpkoVFXvgChyejfQK") catch unreachable).data),
        .static(&(Hash.parseBase58String("CHUQaunM2KYWizY5nXij6Diz8ZyW28oHUxVkXKyy5LMm") catch unreachable).data),
        .static(&(Hash.parseBase58String("B2MF8FcKqEZ3WPtvd1ezKMxj6ZqqaYx93zcYoYUzeRWP") catch unreachable).data),
        .static(&(Hash.parseBase58String("CGikwne3JgRcj3SRLRFvaQPqpyo7i4aopbDA2SfEKg79") catch unreachable).data),
        .static(&(Hash.parseBase58String("44UqPLsQB5V6PeNpV2e58EJbdmbkbJ4yvoUnqYBUwaw1") catch unreachable).data),
        .static(&(Hash.parseBase58String("8F7qs8R2TTXwNxGZUEX29HPNV1sUnCsztdP9Ef9PYQej") catch unreachable).data),
        .static(&(Hash.parseBase58String("JBbMa7FvLKTKnS6pyNirBRfzqUneviw9uyjRxmmthyaw") catch unreachable).data),
        .static(&(Hash.parseBase58String("4piFFXTw2depcwingu1ASVEp8JzkMUNT9LaYKBJ6fmo5") catch unreachable).data),
        .static(&(Hash.parseBase58String("FWgP5PAx6ZgzDKtLoCmPNySXtiyuP9zVD5p93rzwS5Uj") catch unreachable).data),
        .static(&(Hash.parseBase58String("HRtH5B7YADRAJEfEKjYo14EH91VCQewe3yqRPPGcUJdm") catch unreachable).data),
        .static(&(Hash.parseBase58String("6kUT8PQEbe5JqQgr8LNW9cF2XrwENZgsnK43SYgYjSLF") catch unreachable).data),
        .static(&(Hash.parseBase58String("AbDt3gpQSSd4YdAnsAJcdm4hLg3qRJL9fkbqJP1jDG2j") catch unreachable).data),
        .static(&(Hash.parseBase58String("4zXBE8HydrfTudtrF89aL56mQcWWQ67KCG3KJUrsMcE3") catch unreachable).data),
        .static(&(Hash.parseBase58String("5MupSpZXygxYm9pwKFmRCfdSYKnkBrzP1qxsK97aL1Ys") catch unreachable).data),
        .static(&(Hash.parseBase58String("9jLCWhZk9ocdTt24pEyeuLGPdG1yevKt8KQjsy6sTJKy") catch unreachable).data),
        .static(&(Hash.parseBase58String("AKFgCyZQj2s38cUipfEwdUhARbGin46B5rBwW76cysyy") catch unreachable).data),
        .static(&(Hash.parseBase58String("5BZ16sdyyR2fJfhA3QCEV1CVj3m6XwemqTwZB67b521V") catch unreachable).data),
        .static(&(Hash.parseBase58String("2dYuPxZZSkv623zRD8YSFg4j8ARQCfTiy1j1EJSC4YYP") catch unreachable).data),
    });

    var pb_features = std.ArrayList(u64).init(allocator);
    try pb_features.appendSlice(&.{
        8745014806010621437,  12746719326835051004, 14880663656912538106, 16502804345974574076, 7464358868518078470,
        17393716913123127814, 13732971186947990025, 9234785398610438155,  10100493572393353740, 16296103013710192647,
        17577018535179185164, 15385144672585180686, 3448684241958864917,  17425121775286888464, 481301242188996633,
        1624608854989936671,  8981415105600321570,  3506988140780836390,  14653876980770606123, 3134844761944150069,
        2108246348442029111,  18430021276965983279, 1546541898477881404,  1668806835898317887,  3159056460576472129,
        12201061873693628997, 16173071899114884681, 9364770135828226129,  11956187351149349462, 13619680173120471639,
        9384680139578013785,  17161605067322646106, 8372877257610877025,  10333664712133278304, 5412861039235947621,
        3217121781990710377,  1903150015966124144,  5811356261681870964,  6945835685041070712,  1488222585707488897,
        6627214705358915199,  6569666574156438145,  3565309654271330957,  5878493780064894105,  13093381132344442521,
        2084081697521279647,  17477161306362325151, 4229600186559593638,  16787576091139260577, 12062129561695986340,
        2608895128084317349,  2095802506721103016,  1043332425687882412,  16343897547665426086, 9291417354790481071,
        14108717550584606385, 2835248715214383806,  12393656768987710652, 1556389209831850690,  10573955866488464067,
        15646637174429435073, 17368202427824553664, 16689784228110797507, 8919829896206010585,  10374551387690409688,
        10497943877114359008, 3080907063555444452,  8408258262441651948,  5430309645140455150,  4916053440333993713,
        18217605389258098417, 13670794101765931764, 8874445338316567292,  3409744574215488768,  10063831043806321919,
        18374874237651057918, 9179305531911086342,  9366572022445289733,  15380324738982398213, 9097679053262300425,
        10495550516822450953, 7864064290362191627,  18144481263832097545, 5578517568662789904,  11624213139604368141,
        16848847066493635853, 12225317994633210130, 14619788719167645459, 10385816867675816217, 3512547638711095073,
        9113171681910074659,  15971986844778064160, 13831771339838013222, 17303821259868640037, 18441458011090382631,
        11999326408594957611, 15535597526625688877, 5767610882599127859,  14215830687796369199, 16289631300196563759,
        17399141370576840507, 7214857342143386434,  5384249827800624464,  520740239964572501,   6311061834237835095,
        3166764948442193245,  5303753339766582627,  4370055567390280552,  4735839496477279080,  16496703778821928294,
        18162940069776114027, 1198485897243202931,  7862845774565664116,  8819118190285818754,  9953734627229811591,
        10698831373887447946, 2327033929746074006,  3881292352862657435,  18133352788893609373, 18293821216929072545,
        9119622038963368358,  15609181264665189287, 5414484214763729842,  7329498988891357619,  975688835218675129,
        6511130474743735231,  18438685373618101179, 9162963928319863751,  4754971307110775241,  12131964148810607046,
        14333591601570674120, 9339287304698073547,  7100026270969684438,  10857131225954620888, 17801294591820438486,
        5516281661825108445,  16152940683682092504, 6184463475151954912,  16785213942406793693, 12022621848025119714,
        11476252442372581349, 6210313007554900458,  15094721454033211366, 14076166885815648232, 15425406085474705386,
    });

    var pb_accounts = std.ArrayList(pb.AcctState).init(allocator);
    try pb_accounts.appendSlice(&.{
        .{
            .address = .static(&(Pubkey.parseBase58String("2mURtedre68vMJzQnDrb6f4XAuyRm7Tje8pujzDfvD9M") catch unreachable).data),
            .lamports = 9365460398065587802,
            .executable = true,
            .rent_epoch = 5155847230196380021,
            .owner = .static(&(Pubkey.parseBase58String("11111111111111111111111111111111") catch unreachable).data),
        },
        .{
            .address = .static(&(Pubkey.parseBase58String("6CdPUpVZW1aXCK9gfNSjxnrySvH5mGgDdiuerUYeSRxq") catch unreachable).data),
            .lamports = 2149935733931552121,
            .data = .static(&.{
                1,   0,   0,   0,  1,   0,   0,   0,   125, 67,  195, 157, 3,   194, 128, 80,  194, 136, 101, 195, 165, 47,  194, 139, 195, 176, 194, 175, 86,  36,  122, 119,
                194, 139, 50,  32, 105, 195, 158, 10,  14,  194, 185, 55,  195, 158, 195, 173, 15,  97,  195, 159, 57,  1,   38,  95,  195, 174, 194, 182, 36,  65,  96,  194,
                132, 195, 168, 80, 194, 181, 76,  194, 191, 123, 13,  194, 128, 195, 175, 194, 136, 1,   195, 180, 194, 161, 58,  100, 194, 178, 194, 155, 195, 143, 80,  194,
                187, 65,  68,  62, 194, 189, 194, 178, 67,  194, 182, 195, 172, 17,  33,  109,
            }),
            .rent_epoch = 15322425405372815508,
            .owner = .static(&(Pubkey.parseBase58String("11111111111111111111111111111111") catch unreachable).data),
        },
        .{
            .address = .static(&(Pubkey.parseBase58String("SysvarRecentB1ockHashes11111111111111111111") catch unreachable).data),
            .lamports = 2314125629479449457,
            .data = .static(&.{
                70,  0,   0,   0,   0,   0,   0,   0,   95,  71,  195, 183, 4,   194, 156, 194, 158, 195, 143, 15,  194, 159, 76,  27,  54,  194, 168, 84,  194, 167, 91,  103,
                92,  73,  195, 130, 194, 130, 26,  57,  82,  15,  194, 168, 194, 143, 112, 195, 170, 195, 128, 194, 168, 194, 163, 19,  59,  101, 195, 184, 195, 144, 119, 195,
                128, 120, 17,  55,  195, 144, 3,   194, 172, 127, 74,  0,   194, 161, 194, 154, 68,  20,  54,  194, 173, 37,  194, 168, 195, 168, 195, 168, 195, 139, 10,  100,
                194, 159, 39,  195, 181, 80,  194, 187, 195, 147, 194, 190, 194, 161, 195, 128, 195, 128, 59,  194, 154, 195, 186, 93,  195, 155, 195, 184, 74,  194, 155, 70,
                88,  125, 62,  76,  27,  105, 195, 158, 195, 177, 194, 171, 87,  46,  194, 129, 2,   195, 164, 194, 170, 194, 170, 1,   194, 176, 195, 155, 194, 170, 195, 170,
                104, 195, 140, 195, 137, 10,  194, 165, 194, 170, 26,  195, 179, 20,  90,  64,  194, 189, 194, 155, 194, 187, 87,  195, 152, 104, 110, 195, 161, 100, 118, 58,
                36,  195, 181, 85,  125, 38,  194, 166, 57,  194, 190, 194, 175, 195, 133, 195, 139, 195, 128, 194, 187, 195, 133, 195, 164, 9,   194, 129, 194, 189, 195, 147,
                194, 157, 194, 161, 195, 186, 195, 162, 127, 47,  195, 142, 34,  77,  22,  194, 149, 194, 132, 106, 194, 133, 194, 171, 195, 141, 194, 135, 194, 176, 195, 142,
                16,  194, 187, 195, 184, 119, 194, 160, 47,  59,  195, 180, 50,  195, 177, 194, 133, 195, 131, 86,  194, 149, 109, 194, 128, 27,  27,  195, 128, 84,  42,  43,
                31,  10,  40,  195, 178, 194, 177, 194, 170, 78,  194, 140, 40,  194, 178, 194, 148, 64,  2,   194, 160, 195, 173, 194, 155, 195, 191, 60,  195, 172, 194, 160,
                108, 1,   110, 109, 56,  194, 160, 120, 55,  88,  102, 109, 41,  195, 180, 100, 68,  195, 156, 109, 73,  194, 187, 195, 138, 195, 131, 96,  194, 167, 194, 129,
                23,  76,  195, 176, 195, 161, 99,  194, 172, 194, 141, 194, 178, 194, 155, 194, 170, 195, 149, 194, 180, 194, 182, 194, 168, 194, 180, 70,  72,  30,  10,  61,
                105, 36,  98,  14,  195, 132, 62,  30,  58,  194, 140, 195, 191, 98,  194, 191, 21,  38,  102, 19,  195, 130, 70,  194, 183, 1,   195, 157, 58,  127, 17,  94,
                86,  58,  194, 152, 52,  195, 148, 194, 164, 195, 161, 194, 156, 194, 160, 194, 175, 195, 161, 195, 147, 75,  123, 14,  48,  195, 187, 58,  195, 176, 109, 195,
                139, 195, 166, 195, 140, 195, 139, 194, 179, 195, 160, 194, 173, 194, 128, 194, 153, 194, 140, 195, 128, 66,  194, 183, 118, 126, 3,   101, 195, 153, 112, 59,
                14,  59,  76,  46,  195, 136, 195, 183, 195, 149, 61,  195, 187, 4,   23,  194, 133, 42,  20,  194, 169, 194, 134, 194, 155, 20,  111, 195, 188, 194, 146, 195,
                159, 194, 181, 28,  125, 195, 156, 99,  195, 184, 126, 195, 187, 194, 165, 194, 166, 114, 8,   195, 135, 94,  195, 180, 195, 164, 64,  21,  195, 178, 66,  195,
                156, 194, 167, 195, 144, 12,  195, 187, 47,  93,  195, 153, 194, 146, 10,  96,  194, 175, 194, 160, 39,  195, 137, 17,  13,  195, 172, 195, 146, 194, 149, 18,
                194, 157, 116, 63,  194, 177, 37,  12,  195, 145, 195, 137, 94,  195, 140, 194, 159, 120, 1,   61,  44,  84,  7,   195, 137, 103, 60,  79,  195, 174, 195, 133,
                195, 152, 195, 189, 195, 130, 52,  194, 170, 195, 181, 88,  195, 143, 14,  64,  2,   195, 165, 0,   114, 195, 183, 195, 155, 194, 134, 71,  26,  194, 162, 194,
                167, 195, 148, 194, 181, 194, 154, 195, 178, 194, 151, 195, 175, 122, 195, 177, 195, 133, 20,  195, 165, 97,  71,  81,  17,  195, 133, 19,  35,  194, 173, 195,
                147, 33,  126, 195, 158, 194, 136, 27,  7,   7,   111, 53,  195, 185, 75,  194, 146, 73,  195, 177, 195, 161, 195, 168, 195, 146, 195, 188, 124, 26,  194, 156,
                194, 164, 194, 182, 195, 129, 36,  194, 183, 194, 186, 195, 133, 195, 185, 77,  194, 131, 15,  75,  67,  194, 147, 124, 127, 194, 164, 46,  7,   195, 148, 23,
                123, 8,   4,   10,  86,  116, 194, 131, 63,  124, 121, 195, 146, 46,  88,  195, 129, 195, 172, 51,  195, 147, 194, 166, 43,  9,   10,  90,  47,  115, 82,  28,
                195, 130, 0,   126, 50,  194, 140, 195, 162, 195, 144, 61,  195, 153, 194, 184, 1,   55,  35,  17,  195, 139, 51,  36,  195, 161, 35,  195, 134, 195, 182, 119,
                11,  45,  195, 177, 194, 156, 101, 195, 190, 195, 173, 109, 195, 139, 126, 194, 147, 194, 158, 194, 148, 195, 181, 35,  195, 190, 31,  194, 171, 195, 133, 194,
                178, 42,  194, 158, 195, 174, 194, 178, 75,  69,  195, 163, 102, 194, 129, 194, 181, 195, 175, 195, 175, 104, 78,  78,  72,  195, 145, 195, 187, 195, 183, 119,
                194, 151, 2,   30,  194, 130, 194, 182, 195, 159, 194, 134, 115, 195, 140, 195, 151, 3,   195, 167, 195, 169, 11,  194, 135, 195, 130, 195, 152, 194, 160, 84,
                195, 129, 57,  22,  195, 150, 195, 161, 194, 159, 195, 131, 195, 172, 60,  74,  81,  99,  102, 194, 150, 74,  127, 195, 174, 126, 44,  194, 154, 56,  195, 130,
                194, 165, 17,  47,  195, 163, 87,  194, 143, 194, 191, 194, 167, 107, 65,  195, 132, 194, 189, 30,  50,  16,  194, 146, 42,  195, 149, 195, 172, 194, 146, 93,
                55,  194, 140, 90,  195, 184, 194, 171, 36,  7,   41,  68,  194, 179, 194, 175, 195, 186, 194, 176, 22,  110, 194, 181, 194, 158, 195, 153, 67,  123, 57,  93,
                99,  195, 172, 195, 167, 46,  28,  66,  17,  194, 169, 46,  0,   194, 147, 194, 176, 195, 167, 194, 141, 108, 42,  126, 195, 146, 195, 164, 6,   46,  99,  195,
                141, 57,  195, 135, 86,  127, 195, 183, 117, 21,  194, 189, 194, 130, 194, 169, 5,   195, 178, 127, 194, 132, 46,  194, 180, 57,  87,  194, 144, 92,  195, 172,
                195, 160, 16,  195, 159, 194, 130, 16,  194, 133, 74,  39,  195, 169, 194, 146, 12,  195, 184, 55,  73,  40,  194, 129, 72,  105, 194, 179, 11,  2,   84,  194,
                142, 115, 31,  194, 176, 195, 139, 95,  120, 19,  12,  117, 194, 162, 195, 183, 195, 144, 66,  195, 148, 195, 187, 195, 178, 195, 128, 195, 136, 194, 156, 18,
                96,  13,  61,  195, 170, 194, 149, 195, 166, 66,  195, 167, 195, 168, 62,  79,  57,  12,  8,   111, 194, 181, 195, 142, 95,  6,   85,  23,  195, 181, 194, 155,
                7,   82,  90,  195, 156, 194, 175, 194, 187, 194, 151, 195, 185, 92,  194, 149, 195, 181, 194, 134, 194, 140, 78,  195, 151, 61,  195, 153, 119, 63,  4,   53,
                195, 140, 194, 178, 24,  194, 153, 106, 54,  195, 165, 56,  30,  195, 167, 44,  78,  194, 178, 195, 186, 78,  79,  50,  195, 146, 65,  195, 171, 195, 148, 64,
                195, 131, 44,  66,  194, 187, 194, 180, 194, 134, 51,  26,  195, 189, 91,  85,  194, 159, 194, 141, 195, 183, 8,   121, 31,  195, 130, 195, 187, 194, 136, 195,
                133, 194, 151, 194, 178, 43,  195, 172, 20,  126, 25,  195, 183, 97,  79,  60,  18,  10,  114, 195, 188, 21,  194, 144, 0,   195, 172, 64,  195, 153, 195, 169,
                121, 98,  50,  194, 136, 40,  195, 162, 194, 191, 195, 139, 111, 75,  195, 161, 194, 188, 195, 178, 195, 131, 48,  195, 191, 195, 166, 122, 79,  125, 92,  194,
                147, 195, 135, 195, 144, 194, 169, 195, 177, 194, 176, 194, 179, 194, 172, 194, 153, 195, 150, 73,  39,  195, 132, 194, 132, 41,  61,  195, 133, 34,  194, 160,
                89,  195, 187, 87,  194, 134, 114, 97,  79,  195, 165, 110, 118, 194, 147, 195, 154, 117, 195, 188, 194, 173, 61,  111, 194, 178, 194, 164, 195, 165, 195, 182,
                194, 130, 73,  113, 195, 174, 56,  194, 163, 29,  195, 185, 195, 182, 97,  102, 195, 144, 195, 155, 93,  195, 171, 195, 187, 195, 165, 102, 194, 169, 107, 194,
                177, 194, 155, 97,  5,   40,  80,  195, 144, 40,  195, 134, 195, 150, 115, 94,  195, 128, 194, 130, 194, 150, 94,  105, 194, 190, 195, 169, 195, 176, 194, 153,
                124, 195, 136, 195, 137, 194, 178, 195, 175, 195, 141, 33,  195, 128, 127, 195, 148, 60,  102, 194, 169, 7,   81,  194, 191, 194, 170, 39,  62,  194, 128, 195,
                140, 32,  194, 159, 194, 138, 28,  31,  194, 140, 123, 195, 184, 194, 177, 194, 167, 34,  119, 195, 168, 194, 187, 195, 171, 30,  195, 183, 195, 175, 24,  195,
                129, 104, 107, 195, 137, 195, 140, 22,  194, 191, 194, 178, 194, 154, 84,  195, 136, 194, 149, 83,  194, 137, 86,  194, 151, 194, 171, 83,  100, 96,  123, 56,
                195, 178, 23,  37,  117, 50,  21,  194, 191, 57,  16,  194, 153, 195, 169, 11,  195, 153, 195, 189, 195, 181, 195, 164, 194, 187, 194, 128, 99,  43,  108, 99,
                194, 162, 194, 162, 195, 185, 47,  195, 150, 194, 164, 194, 129, 35,  195, 164, 195, 153, 195, 138, 19,  17,  123, 60,  24,  194, 176, 194, 172, 50,  18,  195,
                184, 195, 136, 3,   195, 147, 194, 161, 82,  195, 180, 70,  195, 170, 91,  18,  194, 132, 195, 168, 194, 132, 76,  194, 164, 194, 162, 110, 195, 135, 116, 194,
                131, 194, 137, 11,  194, 134, 55,  55,  195, 161, 195, 149, 110, 62,  110, 195, 179, 194, 175, 195, 128, 63,  55,  195, 155, 57,  194, 142, 122, 195, 167, 58,
                15,  41,  194, 183, 57,  70,  195, 154, 195, 130, 195, 172, 194, 135, 40,  107, 15,  76,  194, 128, 85,  46,  18,  106, 195, 164, 42,  195, 128, 195, 144, 194,
                136, 194, 150, 82,  14,  194, 190, 195, 157, 96,  194, 137, 195, 150, 22,  194, 183, 194, 178, 195, 145, 49,  195, 190, 194, 136, 0,   26,  13,  32,  60,  194,
                137, 60,  195, 183, 195, 180, 0,   195, 136, 91,  194, 157, 195, 148, 194, 137, 194, 131, 195, 176, 194, 160, 194, 171, 30,  194, 148, 195, 144, 194, 188, 120,
                44,  114, 194, 185, 195, 130, 194, 143, 195, 161, 194, 182, 195, 177, 89,  194, 172, 122, 75,  104, 195, 144, 112, 195, 182, 194, 153, 195, 168, 194, 158, 47,
                195, 143, 30,  19,  109, 59,  194, 145, 20,  194, 155, 195, 143, 195, 147, 195, 166, 82,  80,  194, 173, 87,  71,  85,  195, 157, 194, 144, 195, 162, 61,  194,
                137, 194, 186, 107, 195, 155, 50,  195, 137, 45,  116, 94,  195, 174, 195, 152, 195, 162, 10,  11,  73,  6,   11,  25,  111, 52,  194, 141, 107, 194, 159, 61,
                194, 184, 194, 134, 195, 179, 195, 183, 55,  69,  195, 182, 122, 195, 143, 195, 134, 98,  195, 155, 195, 129, 93,  194, 128, 194, 166, 53,  26,  5,   194, 128,
                195, 180, 50,  195, 165, 194, 130, 195, 157, 194, 168, 100, 31,  194, 167, 194, 182, 194, 132, 43,  85,  195, 167, 5,   60,  194, 130, 4,   30,  195, 135, 26,
                194, 169, 194, 144, 119, 63,  194, 129, 123, 194, 189, 194, 141, 82,  85,  62,  31,  194, 181, 80,  16,  35,  194, 153, 194, 183, 195, 150, 194, 179, 195, 135,
                194, 152, 194, 143, 36,  195, 166, 37,  194, 148, 110, 4,   37,  89,  88,  195, 175, 194, 160, 107, 79,  73,  194, 134, 195, 180, 117, 110, 109, 194, 181, 195,
                147, 66,  195, 163, 194, 161, 194, 191, 12,  69,  32,  195, 129, 195, 173, 194, 167, 94,  117, 12,  195, 175, 195, 179, 194, 142, 44,  63,  194, 179, 194, 170,
                86,  194, 154, 194, 151, 38,  194, 131, 15,  194, 164, 26,  195, 181, 195, 131, 195, 153, 102, 195, 171, 195, 135, 194, 175, 194, 165, 195, 146, 195, 183, 195,
                166, 195, 181, 194, 151, 195, 143, 69,  67,  195, 129, 194, 144, 58,  194, 168, 0,   114, 111, 195, 149, 14,  195, 148, 40,  36,  91,  88,  55,  194, 177, 195,
                165, 194, 137, 20,  87,  76,  194, 141, 124, 9,   88,  52,  194, 143, 195, 148, 194, 162, 194, 183, 194, 172, 108, 194, 159, 195, 147, 11,  194, 135, 194, 170,
                98,  80,  52,  194, 171, 24,  195, 188, 96,  103, 64,  195, 175, 194, 167, 96,  195, 153, 195, 157, 195, 145, 21,  9,   195, 153, 194, 148, 109, 10,  194, 131,
                194, 157, 83,  79,  195, 128, 194, 132, 194, 144, 7,   194, 179, 195, 173, 195, 158, 194, 170, 89,  125, 75,  195, 145, 195, 170, 33,  194, 187, 67,  12,  125,
                76,  125, 9,   50,  195, 171, 35,  195, 183, 25,  79,  194, 168, 194, 134, 194, 147, 195, 144, 67,  107, 74,  78,  87,  194, 160, 194, 190, 36,  95,  194, 175,
                63,  96,  29,  195, 171, 194, 155, 195, 176, 31,  79,  194, 145, 118, 100, 194, 176, 66,  29,  194, 176, 61,  3,   68,  37,  194, 131, 108, 195, 150, 17,  106,
                194, 139, 24,  194, 186, 68,  59,  106, 195, 153, 195, 129, 36,  81,  62,  65,  41,  194, 186, 100, 56,  194, 147, 121, 62,  36,  23,  194, 175, 116, 194, 164,
                75,  194, 152, 194, 162, 32,  194, 191, 195, 161, 194, 166, 78,  99,  31,  15,  94,  194, 147, 194, 162, 13,  194, 148, 66,  101, 195, 187, 195, 130, 195, 141,
                58,  89,  195, 141, 195, 185, 194, 170, 49,  195, 182, 194, 182, 86,  195, 137, 68,  71,  23,  21,  194, 146, 195, 190, 194, 190, 61,  194, 166, 6,   195, 130,
                76,  195, 180, 37,  87,  194, 144, 75,  59,  107, 194, 168, 195, 151, 0,   68,  56,  194, 139, 82,  37,  59,  2,   195, 172, 195, 166, 195, 150, 9,   122, 195,
                129, 32,  82,  102, 60,  39,  195, 171, 195, 141, 111, 28,  194, 156, 195, 135, 195, 191, 96,  81,  195, 180, 84,  124, 195, 164, 195, 130, 90,  124, 123, 195,
                143, 106, 194, 130, 194, 145, 34,  98,  195, 149, 49,  195, 132, 195, 180, 19,  194, 168, 2,   194, 128, 122, 23,  195, 150, 195, 164, 14,  112, 46,  126, 194,
                185, 195, 189, 194, 177, 194, 181, 115, 195, 169, 62,  194, 176, 194, 173, 66,  194, 164, 84,  6,   194, 128, 195, 168, 194, 157, 89,  195, 166, 194, 133, 14,
                195, 149, 195, 186, 195, 149, 194, 146, 195, 163, 49,  34,  194, 156, 19,  195, 155, 195, 135, 194, 135, 95,  63,  195, 177, 77,  194, 172, 194, 162, 195, 152,
                75,  194, 188, 18,  194, 143, 6,   194, 180, 48,  195, 191, 195, 176, 49,  194, 151, 117, 118, 43,  195, 189, 78,  194, 128, 194, 157, 54,  27,  94,  195, 133,
                22,  194, 169, 56,  89,  90,  19,  194, 187, 194, 148, 195, 178, 33,  194, 177, 194, 165, 194, 184, 61,  1,   194, 173, 63,  195, 170, 194, 151, 194, 176, 195,
                163, 194, 144, 16,  194, 176, 195, 156, 51,  194, 169, 194, 128, 195, 137, 87,  194, 130, 23,  194, 191, 194, 174, 195, 165, 195, 186, 195, 148, 194, 180, 195,
                186, 195, 158, 3,   104, 98,  107, 195, 189, 8,   74,  33,  51,  60,  195, 131, 194, 177, 194, 156, 82,  195, 161, 83,  124, 63,  105, 195, 129, 195, 141, 97,
                69,  194, 134, 195, 164, 15,  195, 175, 124, 195, 159, 11,  194, 172, 65,  194, 140, 47,  195, 129, 194, 129, 58,  101, 195, 158, 42,  195, 150, 6,   60,  194,
                174, 195, 187, 194, 142, 76,  195, 165, 194, 169, 30,  194, 153, 195, 177, 122, 77,  124, 121, 33,  32,  195, 148, 195, 133, 195, 177, 76,  36,  194, 145, 69,
                62,  194, 166, 195, 130, 0,   47,  194, 128, 194, 141, 195, 179, 104, 194, 132, 7,   76,  8,   21,  126, 194, 167, 194, 136, 69,  51,  194, 162, 10,  7,   74,
                114, 13,  195, 184, 66,  195, 186, 194, 149, 195, 142, 57,  194, 180, 21,  18,  195, 174, 195, 154, 126, 195, 177, 57,  194, 144, 63,  195, 155, 194, 159, 194,
                182, 194, 144, 117, 80,  195, 144, 195, 179, 195, 181, 194, 173, 194, 191, 113, 117, 195, 164, 64,  195, 141, 75,  194, 190, 195, 186, 194, 133, 49,  194, 158,
                194, 152, 3,   75,  195, 169, 31,  60,  52,  195, 171, 194, 138, 6,   27,  14,  195, 186, 83,  195, 143, 110, 195, 132, 105, 32,  112, 194, 175, 121, 41,  39,
                42,  66,  194, 158, 195, 175, 195, 148, 74,  195, 149, 34,  48,  195, 152, 194, 156, 195, 176, 194, 138, 20,  122, 194, 131, 53,  6,   194, 152, 194, 150, 35,
                38,  194, 168, 195, 186, 114, 105, 93,  194, 152, 194, 184, 195, 187, 75,  194, 140, 195, 152, 195, 141, 194, 182, 63,  195, 145, 42,  122, 195, 141, 59,  16,
                60,  194, 179, 194, 177, 52,  71,  194, 170, 88,  28,  195, 145, 110, 55,  30,  2,   195, 148, 195, 140, 195, 190, 194, 163, 195, 159, 108, 195, 157, 194, 187,
                112, 194, 157, 122, 7,   63,  194, 133, 74,  194, 171, 194, 128, 195, 176, 194, 141, 194, 132, 194, 137, 51,  18,  113, 194, 187, 195, 131, 83,  194, 156, 195,
                145, 49,  195, 180, 84,  195, 159, 195, 129, 194, 159, 24,  195, 153, 116, 194, 185, 195, 150, 195, 142, 115, 194, 148, 41,  30,  51,  68,  59,  112, 45,  71,
                195, 153, 99,  83,  194, 128, 114, 194, 164, 104, 194, 161, 195, 130, 23,  121, 195, 191, 195, 153, 84,  194, 150, 62,  194, 165, 194, 140, 72,  87,  194, 165,
                7,   100, 195, 139, 106, 117, 76,  194, 152, 96,  195, 142, 69,  194, 128, 194, 182, 195, 148, 195, 166, 194, 173, 15,  194, 133, 195, 128, 101, 194, 142, 195,
                188, 195, 182, 28,  194, 133, 195, 191, 195, 166, 195, 141, 194, 181, 51,  32,  194, 168, 195, 133, 73,  195, 166, 29,  195, 155, 195, 174, 32,  195, 150, 25,
                66,  195, 140, 194, 177, 115, 195, 133, 195, 133, 195, 186, 115, 195, 140, 194, 143, 195, 181, 195, 163, 44,  194, 129, 38,  80,  125, 195, 180, 195, 130, 56,
                41,  195, 186, 121, 195, 128, 195, 144, 194, 181, 114, 90,  194, 170, 20,  54,  69,  119, 96,  195, 171, 44,  74,  194, 186, 194, 137, 8,   195, 171, 194, 154,
                195, 186, 120, 101, 122, 83,  45,  195, 147, 194, 145, 195, 172, 195, 184, 77,  45,  14,  5,   195, 137, 33,  44,  54,  73,  194, 184, 194, 171, 34,  13,  25,
                111, 195, 130, 120, 194, 166, 194, 159, 65,  195, 156, 16,  20,  16,  194, 186, 194, 164, 194, 141, 194, 137, 21,  76,  10,  195, 178, 194, 161, 194, 160, 194,
                151, 121, 98,  194, 142, 195, 174, 194, 139, 194, 174, 195, 173, 122, 195, 145, 195, 149, 194, 148, 12,  194, 161, 195, 162, 90,  194, 130, 195, 189, 118, 49,
                195, 131, 195, 162, 103, 194, 169, 66,  194, 159, 122, 91,  119, 195, 160, 195, 153, 195, 152, 58,  194, 186, 23,  114, 0,   195, 132, 194, 141, 110, 44,  195,
                191, 195, 157, 21,  195, 176, 89,  195, 162, 195, 150, 113, 195, 164, 194, 151, 1,   195, 145, 73,  195, 155, 194, 176, 195, 134, 58,  195, 187, 64,  194, 157,
                125, 111, 195, 129, 195, 144, 100, 195, 153, 45,  43,  94,  195, 179, 22,  125, 195, 183, 195, 151, 77,  195, 145, 32,  90,  121, 194, 187, 19,  194, 186, 195,
                132, 126, 194, 147, 195, 165, 30,  194, 131, 71,  194, 179, 118, 19,  42,  113, 195, 129, 194, 158, 72,  108, 104, 195, 130, 89,  195, 149, 99,  6,   194, 136,
                194, 160, 194, 165, 2,   104, 194, 175, 47,  34,  36,  194, 142, 195, 178, 194, 152, 194, 135, 195, 164, 101, 93,  195, 156, 194, 147, 114, 195, 176, 194, 170,
                4,   77,  35,  195, 177, 195, 142, 34,  194, 164, 195, 143, 80,  194, 187, 194, 164, 86,  42,  46,  1,   195, 143, 194, 167, 11,  194, 161, 37,  195, 160, 195,
                163, 101, 195, 175, 3,   79,  194, 154, 194, 164, 194, 163, 88,  87,  67,  27,  61,  194, 134, 51,  195, 175, 194, 162, 195, 176, 195, 184, 63,  194, 174, 195,
                129, 77,  194, 158, 49,  194, 188, 194, 181, 64,  195, 177, 194, 154, 113, 44,  194, 154, 195, 147, 194, 153, 195, 163, 194, 144, 194, 148, 101, 195, 149, 195,
                179, 194, 161, 121, 57,  69,  195, 143, 194, 163, 65,  194, 162, 195, 150, 71,  16,  64,  195, 162, 76,  95,  109, 194, 176, 39,  31,  194, 191, 48,  16,  194,
                146, 62,  41,  15,  112, 16,  18,  194, 152, 66,  195, 166, 194, 183, 7,   38,  123, 61,  194, 138, 194, 136, 194, 133, 90,  194, 169, 93,  195, 152, 123, 195,
                147, 84,  194, 128, 194, 189, 17,  22,  195, 172, 194, 153, 86,  86,  26,  195, 170, 195, 137, 194, 185, 194, 133, 8,   195, 173, 117, 2,   76,  88,  115, 194,
                166, 194, 170, 195, 183, 195, 134, 195, 171, 52,  80,  9,   194, 172, 195, 186, 22,  194, 152, 195, 155, 194, 131, 195, 176, 195, 148, 91,  195, 159, 194, 180,
                195, 167, 195, 137, 71,  195, 129, 10,  194, 173, 194, 163, 32,  194, 181, 195, 149, 194, 184, 195, 129, 125, 194, 153, 24,  99,  194, 172, 1,   194, 135, 94,
                89,  35,  194, 150, 22,  195, 148, 195, 170, 195, 144, 97,  124, 194, 177, 107, 36,  54,  195, 143, 7,   195, 170, 107, 53,  194, 158, 194, 152, 194, 144, 195,
                153, 71,  95,  34,  124, 10,  36,  195, 179, 195, 139, 83,  195, 176, 195, 176, 195, 131, 110, 194, 159, 195, 153, 39,  46,  195, 161, 195, 144, 194, 139, 4,
                120, 194, 185, 91,  194, 153, 84,  194, 173, 195, 161, 105, 194, 173, 46,  195, 152, 33,  54,  195, 177, 195, 183, 194, 154, 195, 131, 194, 131, 73,  195, 137,
                195, 186, 195, 191, 61,  195, 143, 59,  3,   194, 132, 195, 149, 21,  8,   195, 172, 31,  195, 132, 65,  195, 159, 195, 154, 194, 132, 85,  114, 195, 160, 85,
                194, 168, 195, 133, 49,  25,  104, 194, 135, 105, 38,  195, 183, 124, 195, 161, 33,  29,  195, 167, 194, 172, 195, 158, 194, 131, 20,  195, 191, 23,  195, 134,
                195, 140, 117, 74,  194, 187, 194, 160, 195, 151, 194, 167, 47,  195, 150, 65,  194, 134, 195, 150, 195, 128, 195, 188, 194, 145, 194, 132, 100, 116, 194, 189,
                194, 171, 194, 176, 194, 150, 89,  194, 132, 194, 176, 194, 143, 195, 180, 194, 157, 80,  195, 183, 195, 130, 31,  195, 152, 195, 189, 194, 169, 72,  124, 43,
                123, 195, 128, 110, 16,  195, 154, 195, 140, 195, 170, 194, 132, 195, 159, 32,  94,  195, 128, 12,  195, 180, 86,  100, 63,  45,  42,  90,  50,  194, 129, 39,
                195, 132, 62,  101, 195, 184, 194, 166, 194, 150, 108, 194, 186, 195, 162, 194, 143, 194, 155, 5,   194, 131, 195, 191, 195, 148, 45,  195, 187, 195, 147, 195,
                164, 110, 195, 156, 86,  194, 171, 195, 191, 195, 176, 88,  195, 134, 194, 141, 194, 136, 11,  194, 129, 110, 68,  114, 119, 14,  102, 194, 185, 113, 194, 167,
                195, 147, 194, 130, 26,  7,   101, 104, 194, 172, 0,   195, 154, 195, 129, 195, 179, 120, 72,  195, 164, 70,  195, 188, 83,  68,  55,  36,  45,  16,  64,  72,
                195, 163, 123, 63,  194, 130, 195, 144, 85,  2,   77,  36,  5,   195, 170, 5,   125, 195, 174, 194, 188, 194, 159, 195, 128, 63,  6,   114, 194, 166, 195, 165,
                194, 187, 0,   123, 194, 189, 122, 117, 120, 91,  75,  195, 163, 195, 152, 16,  194, 129, 194, 155, 106, 116, 108, 47,  86,  102, 117, 194, 166, 12,  14,  194,
                147, 194, 166, 97,  84,  195, 166, 195, 170, 195, 176, 66,  121, 195, 141, 194, 148, 195, 161, 194, 178, 195, 147, 111, 195, 145, 93,  195, 143, 195, 151, 194,
                152, 194, 165, 195, 140, 195, 166, 195, 131, 195, 135, 195, 154, 69,  195, 187, 195, 152, 109, 194, 189, 194, 191, 195, 175, 194, 164, 195, 173, 194, 135, 195,
                133, 194, 160, 194, 167, 195, 153, 21,  115, 195, 155, 195, 172, 194, 176, 194, 187, 194, 153, 195, 171, 194, 179, 194, 169, 124, 194, 166, 194, 143, 195, 142,
                195, 168, 84,  195, 149, 122, 87,  18,  195, 147, 194, 178, 195, 181, 116, 54,  195, 165, 194, 155, 93,  195, 169, 46,  194, 183, 28,  194, 191, 75,  195, 157,
                56,  52,  32,  13,  194, 175, 22,  194, 190, 36,  25,  194, 130, 195, 155, 194, 179, 19,  118, 195, 182, 194, 166, 194, 188, 28,  126, 97,  99,  115, 194, 166,
                112, 195, 161, 5,   194, 129, 46,  60,  195, 181, 31,  195, 185, 194, 185, 194, 128, 82,
            }),
            .rent_epoch = 4691045773770054888,
            .owner = .static(&(Pubkey.parseBase58String("Sysvar1111111111111111111111111111111111111") catch unreachable).data),
        },
        .{
            .address = .static(&(Pubkey.parseBase58String("9Ryytjr8fozTZEy6bUqXC5eU86rtVmPUEmmj7iLUj9Wg") catch unreachable).data),
            .lamports = 7686924270384124087,
            .executable = true,
            .rent_epoch = 7216444550539344568,
            .owner = .static(&(Pubkey.parseBase58String("HfJBAKKCsfwScEwZLKUZau41WVNufhxzmZMnL1B3xNHX") catch unreachable).data),
        },
        .{
            .address = .static(&(Pubkey.parseBase58String("2sndiBU5xRWBk2dGhWU1bZWJopxrmEMitjHAKNvXsyjm") catch unreachable).data),
            .lamports = 5191045593681845111,
            .data = .static(&.{
                1,   0,   0,   0,   195, 191, 195, 191, 195, 191, 195, 191, 195, 191, 195, 191, 195, 191, 195, 191, 44,  194, 173, 195, 183, 40,  0,   0,   0,   0,   0,   1,
                62,  195, 152, 11,  194, 154, 194, 130, 195, 183, 42,  92,  194, 187, 16,  114, 194, 140, 8,   194, 151, 91,  75,  61,  195, 186, 195, 140, 70,  74,  195, 137,
                60,  194, 141, 114, 194, 153, 9,   40,  59,  105, 27,  194, 145, 194, 177, 195, 168, 6,   194, 167, 195, 149, 23,  25,  44,  86,  194, 142, 195, 160, 194, 138,
                194, 132, 95,  115, 195, 146, 194, 151, 194, 136, 195, 143, 3,   1,   69,  194, 178, 26,  194, 179, 68,  195, 152, 6,   46,  194, 169, 64,  0,   0,
            }),
            .rent_epoch = 3739901766483084015,
            .owner = .static(&(Pubkey.parseBase58String("AddressLookupTab1e1111111111111111111111111") catch unreachable).data),
        },
    });

    var pb_tx = pb.SanitizedTransaction{
        .message = .{
            .header = .{
                .num_required_signatures = 3,
                .num_readonly_unsigned_accounts = 1,
            },
            .account_keys = .init(allocator),
            .recent_blockhash = .static(&(Pubkey.parseBase58String("5VM6f4cVttMPcqEovhp9fg2ipKqAsQ2U23mrcUfJWgm") catch unreachable).data),
            .instructions = .init(allocator),
            .address_table_lookups = .init(allocator),
        },
        .message_hash = .static(&(Hash.parseBase58String("11111111111111111111111111111111") catch unreachable).data),
        .signatures = .init(allocator),
    };

    try pb_tx.message.?.account_keys.appendSlice(&.{
        .static(&(Pubkey.parseBase58String("2mURtedre68vMJzQnDrb6f4XAuyRm7Tje8pujzDfvD9M") catch unreachable).data),
        .static(&(Pubkey.parseBase58String("9Ryytjr8fozTZEy6bUqXC5eU86rtVmPUEmmj7iLUj9Wg") catch unreachable).data),
        .static(&(Pubkey.parseBase58String("6CdPUpVZW1aXCK9gfNSjxnrySvH5mGgDdiuerUYeSRxq") catch unreachable).data),
        .static(&(Pubkey.parseBase58String("11111111111111111111111111111111") catch unreachable).data),
    });

    try pb_tx.message.?.instructions.appendSlice(&.{.{
        .program_id_index = 3,
        .accounts = .init(allocator),
        .data = .static(&.{ 4, 0, 0, 0 }),
    }});
    try pb_tx.message.?.instructions.items[0].accounts.appendSlice(&.{ 2, 4, 1, 3 });

    try pb_tx.message.?.address_table_lookups.appendSlice(&.{.{
        .account_key = .static(&(Pubkey.parseBase58String("2sndiBU5xRWBk2dGhWU1bZWJopxrmEMitjHAKNvXsyjm") catch unreachable).data),
        .writable_indexes = .init(allocator),
        .readonly_indexes = .init(allocator),
    }});
    try pb_tx.message.?.address_table_lookups.items[0].readonly_indexes.append(0);

    try pb_tx.signatures.appendSlice(&.{
        .static(&(Signature.parseBase58String("5J6RCYMNCZq2kqTHLS1XCHqtSTBEn6uVbyqa6wbrXAdXGQreHdjRvKufeWVbqhWHG6ATno74rEyzuvLbidVq1Pq9") catch unreachable).data),
        .static(&(Signature.parseBase58String("ePsUp71bQrtnkePWJZDsV67LUFc9k35RtPEP8bvK3U1YemiHaNxz9UJZq39dd1GZXx9GRNxSU2QEH18EHMRiAHu") catch unreachable).data),
        .static(&(Signature.parseBase58String("4Hdo6guPkSQ31Y1KHMKtKG69Uu7asCZuccqQUWeFnFGaAwSZdgG98Hsx7hrQ6BjTMjXFdYZim3qsNQ93JcKXUSNb") catch unreachable).data),
    });

    return pb.TxnContext{
        .slot_ctx = pb.SlotContext{ .slot = pb_slot },
        .epoch_ctx = .{ .features = .{ .features = pb_features } },
        .blockhash_queue = pb_blockhashes,
        .account_shared_data = pb_accounts,
        .tx = pb_tx,
    };
}
