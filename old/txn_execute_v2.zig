const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const setup = @import("txn_setup.zig");
const sig = @import("sig");
const std = @import("std");

const sysvar = sig.runtime.sysvar;
const features = sig.runtime.features;

const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const Transaction = sig.core.Transaction;
const AccountSharedData = sig.runtime.AccountSharedData;

const Ancestors = sig.core.status_cache.Ancestors;
const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;
const TransactionVersion = sig.core.transaction.Version;
const TransactionMessage = sig.core.transaction.Message;
const TransactionInstruction = sig.core.transaction.Instruction;
const TransactionAddressLookup = sig.core.transaction.AddressLookup;
const FeeRateGovernor = sig.core.FeeRateGovernor;
const GenesisConfig = sig.core.GenesisConfig;
const Inflation = sig.core.Inflation;
const PohConfig = sig.core.PohConfig;
const SysvarCache = sig.runtime.SysvarCache;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const TransactionExecutionEnvironment = sig.runtime.transaction_execution.TransactionExecutionEnvironment;
const TransactionExecutionConfig = sig.runtime.transaction_execution.TransactionExecutionConfig;
const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const loadAndExecuteTransaction = sig.runtime.transaction_execution.loadAndExecuteTransaction;

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

const FEE_COLLECTOR_PUBKEY = Pubkey.parseBase58String("1111111111111111111111111111111111") catch unreachable;
const DEFAULT_SLOT: u64 = 10;

fn executeTxnContext(allocator: std.mem.Allocator, pb_txn_ctx: pb.TxnContext, emit_logs: bool) !pb.TxnResult {
    // TxnContext (Flattened)
    // slot: u64
    // features: ?Features
    // blockhash_queue: ArrayList(ManagedString)
    // account_shared_data: ArrayList(AccountSharedData)
    // sanitized_transaction: SanitizedTransaction

    errdefer |err| {
        std.debug.print("executeTxnContext: {s}\n", .{@errorName(err)});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }
    var prng = std.Random.DefaultPrng.init(try generateSeed(pb_txn_ctx));

    var feature_set = try setup.loadFeatureSet(allocator, pb_txn_ctx.epoch_ctx);
    defer feature_set.deinit(allocator);

    try setup.toggleDirectMapping(allocator, &feature_set);

    const genesis_config = try setup.initGenesisConfig(
        allocator,
        pb_txn_ctx.account_shared_data.items,
    );
    defer genesis_config.deinit(allocator);

    const blockhashes = try setup.loadBlockhashes(
        allocator,
        pb_txn_ctx.blockhash_queue.items,
    );
    defer allocator.free(blockhashes);

    var loaded_accounts = std.AutoArrayHashMap(Pubkey, struct { u64, AccountSharedData }){};
    defer {
        for (loaded_accounts.values()) |v| v[1].data.deinit(allocator);
        loaded_accounts.deinit(allocator);
    }
    try setup.loadBuiltins(allocator, &loaded_accounts);
    try setup.loadPrecompiles(allocator, &loaded_accounts);

    // // genesis needs stakes for all epochs up to the epoch implied by
    // //  slot = 0 and genesis configuration
    // {
    //     let stakes = bank.stakes_cache.stakes().clone();
    //     let stakes = Arc::new(StakesEnum::from(stakes));
    //     for epoch in 0..=bank.get_leader_schedule_epoch(bank.slot) {
    //         bank.epoch_stakes
    //             .insert(epoch, EpochStakes::new(stakes.clone(), epoch));
    //     }
    //     bank.update_stake_history(None);
    // }
    // bank.update_clock(None);
    // bank.update_rent();
    // bank.update_epoch_schedule();
    // bank.update_recent_blockhashes();
    // bank.update_last_restart_slot();

    // var loaded_accounts = std.AutoArrayHashMap(Pubkey, struct { u64, AccountSharedData }){};
    // defer {
    //     for (loaded_accounts.values()) |v| v[1].data.deinit(allocator);
    //     loaded_accounts.deinit(allocator);
    // }

    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, 0, {});

    const fee_rate_govenor = genesis_config.fee_rate_governor;
    // for (genesis_config.accounts.iterator()) |item| {
    //     // put accounts
    //     _ = item;
    // }
    // for (genesis_config.rewards_pools.iterator()) |item| {
    //     // put rewards pools
    //     _ = item;
    // }

    var blockhahs_queue = sig.core.bank.BlockhashQueue{};
    defer blockhahs_queue.deinit(allocator);
    try blockhahs_queue.insertGenesisHash(
        allocator,
        blockhashes[0],
        fee_rate_govenor.lamports_per_signature,
    );

    // READ SLOT
    const slot = if (pb_txn_ctx.slot_ctx) |ctx| ctx.slot else DEFAULT_SLOT;
    std.debug.print("Slot: {d}\n", .{slot});

    if (slot > 0) {
        try ancestors.ancestors.put(allocator, slot, {});
        fee_rate_govenor = FeeRateGovernor.initDerived(&fee_rate_govenor, 0);
    }
    std.debug.print("Ancestors: {any}\n", .{ancestors.ancestors.keys()});

    // Load accounts and sysvars
    const sysvar_cache = SysvarCache{};

    _ = sysvar_cache;
    _ = emit_logs;

    return .{};

    // const sanitized_transaction = try parseSanitizedTransaction(
    //     allocator,
    //     pb_txn_ctx.tx.?,
    // );
    // defer sanitized_transaction.deinit(allocator);

    // const verify_transaction_result = try verifyTransaction(
    //     allocator,
    //     sanitized_transaction,
    //     &feature_set,
    //     &accounts_db,
    // );

    // const runtime_transaction: RuntimeTransaction = switch (verify_transaction_result) {
    //     .ok => |txn| txn,
    //     .err => |err| return err,
    // };

    // _ = runtime_transaction;
    // _ = emit_logs;

    // const environment = TransactionExecutionEnvironment{
    // ancestors: *const Ancestors,
    // feature_set: *const FeatureSet,
    // status_cache: *const StatusCache,
    // sysvar_cache: *const SysvarCache,
    // rent_collector: *const RentCollector,
    // blockhash_queue: *const BlockhashQueue,
    // epoch_stakes: *const EpochStakes,
    // vm_environment: *const vm.Environment,
    // next_vm_environment: ?*const vm.Environment,

    // slot: u64,
    // max_age: u64,
    // last_blockhash: Hash,
    // next_durable_nonce: Hash,
    // next_lamports_per_signature: u64,
    // last_lamports_per_signature: u64,

    // lamports_per_signature: u64,
    // };

    // const config = TransactionExecutionConfig{
    //     .log = true,
    //     .log_messages_byte_limit = null,
    // };

    // const result = try loadAndExecuteTransaction(
    //     allocator,
    //     &runtime_transaction,
    //     &account_cache,
    //     &environment,
    //     &config,
    // );
}

const VerifyTransactionResult = union(enum(u8)) {
    ok: RuntimeTransaction,
    err: pb.TxnResult,
};

const FeatureSet = sig.runtime.FeatureSet;
const AccountsDb = sig.accounts_db.AccountsDB;

fn verifyTransaction(
    allocator: std.mem.Allocator,
    transaction: Transaction,
    feature_set: *const FeatureSet,
    accounts_db: *AccountsDb,
) !VerifyTransactionResult {
    const serialized_msg = transaction.msg.serializeBounded(
        transaction.version,
    ) catch {
        std.debug.print("SanitizedTransaction.msg.serializeBounded failed\n", .{});
        return .{ .err = .{
            .sanitization_error = true,
            .status = transactionErrorToInt(.SanitizeFailure),
        } };
    };
    const msg_hash = sig.core.transaction.Message.hash(serialized_msg.slice());

    if (!feature_set.active.contains(features.MOVE_PRECOMPILE_VERIFICATION_TO_SVM)) {
        const maybe_verify_error = try sig.runtime.program.precompiles.verifyPrecompiles(
            allocator,
            transaction,
            feature_set,
        );
        if (maybe_verify_error) |verify_error| {
            std.debug.print("Precompile verification failed\n", .{});
            const instr_err, const instr_idx, const custom_err = switch (verify_error) {
                .InstructionError => |err| blk: {
                    const instr_err = sig.core.instruction.intFromInstructionErrorEnum(err[1]);
                    const custom_err = switch (err[1]) {
                        .Custom => |e| e,
                        else => 0,
                    };
                    break :blk .{ instr_err, err[0], custom_err };
                },
                else => .{ 0, 0, 0 },
            };
            return .{ .err = .{
                .sanitization_error = true,
                .status = transactionErrorToInt(verify_error),
                .instruction_error = instr_err,
                .instruction_error_index = instr_idx,
                .custom_error = custom_err,
            } };
        }
    }

    const resolved_batch = sig.replay.resolve_lookup.resolveBatch(
        allocator,
        // NOTE: Need ancestors to load with fixed root
        accounts_db,
        &.{transaction},
    ) catch |err| {
        const err_code = switch (err) {
            error.Overflow => 123456,
            error.OutOfMemory => return error.OutOfMemory,
            error.UnsupportedVersion => transactionErrorToInt(.UnsupportedVersion),
            error.AddressLookupTableNotFound => transactionErrorToInt(.AddressLookupTableNotFound),
            error.InvalidAddressLookupTableOwner => transactionErrorToInt(.InvalidAddressLookupTableOwner),
            error.InvalidAddressLookupTableData => transactionErrorToInt(.InvalidAddressLookupTableData),
            error.InvalidAddressLookupTableIndex => transactionErrorToInt(.InvalidAddressLookupTableIndex),
        };
        std.debug.print("resolve_lookup.resolveBatch failed\n", .{});
        return .{ .err = .{
            .sanitization_error = true,
            .status = err_code,
        } };
    };
    defer resolved_batch.deinit(allocator);

    const resolved_txn = resolved_batch.transactions[0];

    return .{ .ok = .{
        .signature_count = resolved_txn.transaction.signatures.len,
        .fee_payer = resolved_txn.transaction.msg.account_keys[0],
        .msg_hash = msg_hash,
        .recent_blockhash = resolved_txn.transaction.msg.recent_blockhash,
        .instruction_infos = resolved_txn.instructions,
        .accounts = resolved_txn.accounts,
    } };
}

fn generateSeed(pb_txn_ctx: pb.TxnContext) !u64 {
    var hasher = std.crypto.hash.Blake3.init(.{});
    const bytes: []const u8 = @as([*]const u8, @ptrCast(&pb_txn_ctx))[0..@sizeOf(pb.TxnContext)];
    hasher.update(bytes);
    var seed = Hash.ZEROES;
    hasher.final(&seed.data);
    return std.mem.bytesAsValue(u64, seed.data[0..8]).*;
}

fn parseSanitizedTransaction(
    allocator: std.mem.Allocator,
    pb_txn: pb.SanitizedTransaction,
) !Transaction {
    const signatures = try allocator.alloc(
        Signature,
        @max(pb_txn.signatures.items.len, 1),
    );
    for (pb_txn.signatures.items, 0..) |pb_signature, i|
        signatures[i] = .{ .data = pb_signature.getSlice()[0..Signature.SIZE].* };
    if (pb_txn.signatures.items.len == 0) signatures[0] = Signature.ZEROES;

    const version, const message = try parseTransactionMesssage(
        allocator,
        pb_txn.message.?,
    );
    return .{
        .signatures = signatures,
        .version = version,
        .msg = message,
    };
}

fn parseTransactionMesssage(
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

fn verifyErrorToInt(err: sig.core.transaction.Transaction.VerifyError) u32 {
    return switch (err) {
        error.SignatureVerificationFailed => transactionErrorToInt(.SignatureFailure),
        error.SerializationFailed => transactionErrorToInt(.SanitizeFailure),
        else => std.debug.panic("Should not happen: {s}", .{@errorName(err)}),
    };
}

fn transactionErrorToInt(err: sig.ledger.transaction_status.TransactionError) u32 {
    return switch (err) {
        .AccountInUse => 1,
        .AccountLoadedTwice => 2,
        .AccountNotFound => 3,
        .ProgramAccountNotFound => 4,
        .InsufficientFundsForFee => 5,
        .InvalidAccountForFee => 6,
        .AlreadyProcessed => 7,
        .BlockhashNotFound => 8,
        .InstructionError => |_| 9,
        .CallChainTooDeep => 10,
        .MissingSignatureForFee => 11,
        .InvalidAccountIndex => 12,
        .SignatureFailure => 13,
        .InvalidProgramForExecution => 14,
        .SanitizeFailure => 15,
        .ClusterMaintenance => 16,
        .AccountBorrowOutstanding => 17,
        .WouldExceedMaxBlockCostLimit => 18,
        .UnsupportedVersion => 19,
        .InvalidWritableAccount => 20,
        .WouldExceedMaxAccountCostLimit => 21,
        .WouldExceedAccountDataBlockLimit => 22,
        .TooManyAccountLocks => 23,
        .AddressLookupTableNotFound => 24,
        .InvalidAddressLookupTableOwner => 25,
        .InvalidAddressLookupTableData => 26,
        .InvalidAddressLookupTableIndex => 27,
        .InvalidRentPayingAccount => 28,
        .WouldExceedMaxVoteCostLimit => 29,
        .WouldExceedAccountDataTotalLimit => 30,
        .DuplicateInstruction => |_| 31,
        .InsufficientFundsForRent => |_| 32,
        .MaxLoadedAccountsDataSizeExceeded => 33,
        .InvalidLoadedAccountsDataSizeLimit => 34,
        .ResanitizationNeeded => 35,
        .ProgramExecutionTemporarilyRestricted => |_| 36,
        .UnbalancedTransaction => 37,
        .ProgramCacheHitMaxLimit => 38,
    };
}

// var initial_accounts = std.AutoArrayHashMap(Pubkey, AccountSharedData){};
// defer {
//     for (initial_accounts.values()) |v| allocator.free(v.data);
//     initial_accounts.deinit(allocator);
// }

// for (genesis_config.accounts.keyIterator(), genesis_config.accounts.valueIterator()) |key, account| {
//     try initial_accounts.put(key, account);
// }
// for (genesis_config.rewards_pools.keyIterator(), genesis_config.rewards_pools.valueIterator()) |key, account| {
//     try initial_accounts.put(key, account);
// }

// const accounts = try allocator.alloc(sig.core.Account, pb_txn_ctx.account_shared_data.items.len);
// defer allocator.free(accounts);
// const keys = try allocator.alloc(Pubkey, pb_txn_ctx.account_shared_data.items.len);
// defer allocator.free(keys);
// for (pb_txn_ctx.account_shared_data.items, 0..) |account, i| {
//     accounts[i] = .{
//         .data = .initAllocated(account.data.getSlice()),
//         .executable = account.executable,
//         .owner = Pubkey{ .data = account.owner.getSlice()[0..Pubkey.SIZE].* },
//         .lamports = account.lamports,
//         .rent_epoch = account.rent_epoch,
//     };
//     keys[i] = Pubkey{ .data = account.address.getSlice()[0..Pubkey.SIZE].* };
// }

// try accounts_db.putAccountSlice(
//     accounts,
//     keys,
//     slot,
// );

// // Provide default slot hashes of size 1 if not provided
// _ = loadSysvar(
//     allocator,
//     SlotHashes,
//     &accounts,
// ) orelse blk: {
//     const slot_hashes = SlotHashes{
//         .entries = try allocator.dupe(struct { u64, Hash }, &.{.{ slot, Hash.ZEROES }}),
//     };

//     const slot_hashes_data = try allocator.alloc(u8, SlotHashes.SIZE_OF);
//     errdefer allocator.free(slot_hashes_data);

//     try bincode.writeToSlice(slot_hashes_data, slot_hashes, .{});

//     accounts.put(allocator, SlotHashes.ID, .{
//         .lamports = @max(1, rent.minimumBalance(slot_hashes_data.len)),
//         .data = slot_hashes_data,
//         .owner = sysvar.OWNER_ID,
//         .executable = false,
//         .rent_epoch = 0,
//     });

//     break :blk slot_hashes;
// };

// // Provide default stake history if not provided
// _ = loadSysvar(
//     allocator,
//     StakeHistory,
//     &accounts,
// ) orelse blk: {
//     const stake_history = StakeHistory{
//         .entries = try allocator.dupe(
//             struct { u64, StakeHistory.Entry },
//             &.{.{ 0, .{ .effective = 0, .activating = 0, .deactivating = 0 } }},
//         ),
//     };

//     const stake_history_data = try allocator.alloc(u8, StakeHistory.SIZE_OF);
//     errdefer allocator.free(stake_history_data);

//     try bincode.writeToSlice(stake_history_data, stake_history, .{});

//     accounts.put(allocator, StakeHistory.ID, .{
//         .lamports = @max(1, rent.minimumBalance(stake_history_data.len)),
//         .data = stake_history_data,
//         .owner = sysvar.OWNER_ID,
//         .executable = false,
//         .rent_epoch = 0,
//     });

//     // TODO: stake_history_update

//     break :blk stake_history;
// };

// // Provide default last restart slot sysvar if not provided
// _ = loadSysvar(
//     allocator,
//     LastRestartSlot,
//     &accounts,
// ) orelse blk: {
//     const last_restart_slot = LastRestartSlot{
//         .last_restart_slot = 0,
//     };

//     const last_restart_slot_data = try allocator.alloc(u8, LastRestartSlot.SIZE_OF);
//     errdefer allocator.free(last_restart_slot_data);

//     try bincode.writeToSlice(last_restart_slot_data, last_restart_slot, .{});

//     accounts.put(allocator, LastRestartSlot.ID, .{
//         .lamports = @max(1, rent.minimumBalance(last_restart_slot_data.len)),
//         .data = last_restart_slot_data,
//         .owner = sysvar.OWNER_ID,
//         .executable = false,
//         .rent_epoch = 0,
//     });

//     break :blk last_restart_slot;
// };

// // Provide a default clock if not present
// _ = loadSysvar(
//     allocator,
//     Clock,
//     &accounts,
// ) orelse blk: {
//     const clock = Clock{
//         .epoch = 0,
//         .epoch_start_timestamp = 0,
//         .unix_timestamp = 0,
//         .slot = slot,
//         .leader_schedule_epoch = 1,
//     };

//     const clock_data = try allocator.alloc(u8, Clock.SIZE_OF);
//     errdefer allocator.free(clock_data);

//     try bincode.writeToSlice(clock_data, clock, .{});

//     accounts.put(allocator, Clock.ID, .{
//         .lamports = @max(1, rent.minimumBalance(clock_data.len)),
//         .data = clock_data,
//         .owner = sysvar.OWNER_ID,
//         .executable = false,
//         .rent_epoch = 0,
//     });

//     // TODO: stake_history_update

//     break :blk clock;
// };

// // Epoch schedule and rent get set from the epoch bank

// var ancestors = Ancestors{};
// defer ancestors.deinit(allocator);

// var status_cache = StatusCache.default();
// defer status_cache.deinit(allocator);

// var sysvar_cache = SysvarCache{};
// defer sysvar_cache.deinit(allocator);

// const rent_collector = RentCollector{
//     .epoch = 0,
//     .epoch_schedule = .DEFAULT,
//     .slots_per_year = 0,
//     .rent = .{
//         .lamports_per_byte_year = 0,
//         .exemption_threshold = 0,
//         .burn_percent = 0,
//     },
// };

// var blockhash_queue = BlockhashQueue.init(300);
// defer blockhash_queue.deinit(allocator);

// var epoch_stakes = EpochStakes.EMPTY;
// defer epoch_stakes.deinit(allocator);

// _ = slot;
// _ = feature_set;
// _ = blockhashes;
// _ = accounts;
// _ = transaction;
// _ = rent_collector;
