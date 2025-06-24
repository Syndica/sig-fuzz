const effects = @import("effects.zig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const setup = @import("setup.zig");
const sig = @import("sig");
const std = @import("std");

const sysvar = sig.runtime.sysvar;
const features = sig.runtime.features;

const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const Transaction = sig.core.Transaction;
const AccountSharedData = sig.runtime.AccountSharedData;

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

    // printPbTxnContext(ctx) catch |err| {
    //     std.debug.print("printPbTxnContext: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result = executeTxnContext(allocator, pb_txn_ctx, EMIT_LOGS) catch |err| {
        std.debug.print("executeTxnContext: {s}\n", .{@errorName(err)});
        return 0;
    };

    // printPbTxnEffects(result) catch |err| {
    //     std.debug.print("printPbTxnEffects: {s}\n", .{@errorName(err)});
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

/// feature_set: FeatureSet <- Toggle Direct Mapping <- TxnContext.EpochContext.Features
/// fee_collector: Pubkey <- Pubkey::new_unique()
/// slot: u64 <- TxnContext.SlotContext.Slot | 10
/// rent: Rent <- TxnContext.[]Accounts.Rent | Rent::default()
/// epoch_schedule: EpochSchedule <- TxnContext[]Accounts.EpochSchedule | EpochSchedule::default()
/// genesis_config: GenesisConfig <- GenesisConfig.accounts.add(alut.id & config.id) <- GenesisConfig{creation_time: 0, rent, epoch_schedule, ..default()})
/// blockhashqueue: BlockhashQueue <- TxnContext.BlockhashQueue | [[[0; 32]]]
/// genesis_hash: Hash <- blockhashqueue.root()
///
/// bank_forks: BankForks <- BankForks::new_rc_arc( Bank::new_with_paths(...))
/// bank: Bank <- bank_forks.root()
/// account_keys: []Pubkey <- TxnContext.SanitizedTransaction.TransactionMessage.[]Pubkey
/// lamports_per_signature: u64 <- TxnContext[]Accounts.RecentBlockhashes.lamports_per_signature | None
/// message: TransactionMessage <- build_versioned_message(TxnContext.SantizedTransaction.TransactionMessage)
/// signatures: []Signature <- TxnContext.SanitizedTransaction.Signatures
/// versioned_transaction: VersionedTransaction <- VersionedTransaction{signatures, transactions}
/// sanitized_transaction: SanitizedTransaction <- bank.verify(versioned_transaction)
/// batch: TransactionBatch <- bank.prepare_sanitized_batch([sanitized_transactin])
/// recording_config
/// timings
/// config
/// metrics
/// result: TransactionProcessingResult <- bank.load_and_execute_transactions(batch, ...)
/// txn_result: TxnResult <- convert result to TxnResult
const DEFAULT_SLOT: u64 = 10; // Arbitrary default > 10

fn executeTxnContext(allocator: std.mem.Allocator, pb_txn_ctx: pb.TxnContext, emit_logs: bool) !pb.TxnResult {
    errdefer |err| {
        std.debug.print("executeTxnContext: {s}\n", .{@errorName(err)});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }
    var prng = std.Random.DefaultPrng.init(try generateSeed(pb_txn_ctx));

    const feature_set = try setup.loadFeatureSet(allocator, pb_txn_ctx.epoch_ctx);
    defer feature_set.deinit(allocator);

    // TODO: Toggle direct mapping

    const fee_collector = Pubkey.initRandom(prng.random());
    const slot = if (pb_txn_ctx.slot_ctx) |ctx| ctx.slot else DEFAULT_SLOT;

    const rent = (try setup.loadSysvar(
        allocator,
        sysvar.Rent,
        pb_txn_ctx.account_shared_data.items,
    )) orelse sysvar.Rent.DEFAULT;

    const epoch_schedule = (try setup.loadSysvar(
        allocator,
        sysvar.EpochSchedule,
        pb_txn_ctx.account_shared_data.items,
    )) orelse sysvar.EpochSchedule.DEFAULT;

    var genesis_config = GenesisConfig.default(allocator);
    defer genesis_config.deinit(allocator);

    genesis_config.creation_time = 0;
    genesis_config.rent = rent;
    genesis_config.epoch_schedule = epoch_schedule;

    var blockhashes = std.ArrayList(Hash).init(allocator);
    defer blockhashes.deinit();

    for (pb_txn_ctx.blockhash_queue.items) |pb_blockhash| {
        const blockhash = Hash{ .data = pb_blockhash.getSlice()[0..Hash.SIZE].* };
        try blockhashes.append(blockhash);
    }

    if (blockhashes.items.len == 0) try blockhashes.append(Hash.ZEROES);

    const genesis_hash = blockhashes.items[0];

    const snapshot_dir_name = try std.fmt.allocPrint(
        allocator,
        "snapshot-dir-{}",
        .{prng.random().int(u64)},
    );
    defer allocator.free(snapshot_dir_name);
    try std.fs.cwd().makeDir(snapshot_dir_name);
    defer std.fs.cwd().deleteTree(snapshot_dir_name) catch {};
    const snapshot_dir = try std.fs.cwd().openDir(
        snapshot_dir_name,
        .{ .iterate = true },
    );

    var accounts_db = try sig.accounts_db.AccountsDB.init(.{
        .allocator = allocator,
        .logger = .noop,
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 1,
        .buffer_pool_frames = 1024,
    });
    defer accounts_db.deinit();

    const accounts = try allocator.alloc(sig.core.Account, pb_txn_ctx.account_shared_data.items.len);
    defer allocator.free(accounts);
    const keys = try allocator.alloc(Pubkey, pb_txn_ctx.account_shared_data.items.len);
    defer allocator.free(keys);
    for (pb_txn_ctx.account_shared_data.items, 0..) |account, i| {
        accounts[i] = .{
            .data = .initAllocated(account.data.getSlice()),
            .executable = account.executable,
            .owner = Pubkey{ .data = account.owner.getSlice()[0..Pubkey.SIZE].* },
            .lamports = account.lamports,
            .rent_epoch = account.rent_epoch,
        };
        keys[i] = Pubkey{ .data = account.address.getSlice()[0..Pubkey.SIZE].* };
    }

    std.debug.print("Putting accounts into AccountsDB\n", .{});
    for (keys, accounts) |key, account| {
        std.debug.print("{} {} {any}\n", .{ slot, key, account });
    }

    try accounts_db.putAccountSlice(
        accounts,
        keys,
        slot,
    );

    const rkeys = [_]Pubkey{
        Pubkey.parseBase58String("11111111111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("AddressLookupTab1e1111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("BPFLoader1111111111111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("BPFLoader2111111111111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("BPFLoaderUpgradeab1e11111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("ComputeBudget111111111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("Config1111111111111111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("Ed25519SigVerify111111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("KeccakSecp256k11111111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("Stake11111111111111111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("SysvarC1ock11111111111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("SysvarEpochSchedu1e111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("SysvarRecentB1ockHashes11111111111111111111") catch unreachable,
        Pubkey.parseBase58String("SysvarRent111111111111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("SysvarStakeHistory1111111111111111111111111") catch unreachable,
        Pubkey.parseBase58String("Vote111111111111111111111111111111111111111") catch unreachable,
    };
    std.debug.print("Bank Accounts:\n", .{});
    for (rkeys) |key| {
        _ = accounts_db.getAccount(&key) catch {
            std.debug.print("{} not found\n", .{key});
            continue;
        };
        std.debug.print("{}\n", .{key});
    }

    // TODO: Analogous Bank setup

    const sanitized_transaction = try parseSanitizedTransaction(
        allocator,
        pb_txn_ctx.tx.?,
    );
    defer sanitized_transaction.deinit(allocator);

    const serialized_msg = sanitized_transaction.msg.serializeBounded(
        sanitized_transaction.version,
    ) catch {
        std.debug.print("SanitizedTransaction.msg.serializeBounded failed\n", .{});
        return .{
            .sanitization_error = true,
            .status = transactionErrorToInt(.SanitizeFailure),
        };
    };
    const msg_hash = sig.core.transaction.Message.hash(serialized_msg.slice());

    if (!feature_set.active.contains(features.MOVE_PRECOMPILE_VERIFICATION_TO_SVM)) {
        const maybe_verify_error = try sig.runtime.program.precompiles.verifyPrecompiles(
            allocator,
            sanitized_transaction,
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
            return .{
                .sanitization_error = true,
                .status = transactionErrorToInt(verify_error),
                .instruction_error = instr_err,
                .instruction_error_index = instr_idx,
                .custom_error = custom_err,
            };
        }
    }

    const resolved_batch = sig.replay.resolve_lookup.resolveBatch(
        allocator,
        // NOTE: Need ancestors to load with fixed root
        &accounts_db,
        &.{sanitized_transaction},
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
        return .{
            .sanitization_error = true,
            .status = err_code,
        };
    };
    defer resolved_batch.deinit(allocator);

    const resolved_txn = resolved_batch.transactions[0];
    const runtime_batch = &[_]RuntimeTransaction{.{
        .signature_count = resolved_txn.transaction.signatures.len,
        .fee_payer = resolved_txn.transaction.msg.account_keys[0],
        .msg_hash = msg_hash,
        .recent_blockhash = resolved_txn.transaction.msg.recent_blockhash,
        .instruction_infos = resolved_txn.instructions,
        .accounts = resolved_txn.accounts,
    }};

    std.debug.print("Successfully parsed transaction\n", .{});

    _ = emit_logs;
    _ = fee_collector;
    _ = genesis_hash;
    _ = runtime_batch;

    // TODO: Replay Verify Transaction producing a RuntimeTransaction

    // Genesis Config -> Default(context epoch schedule, context rent, ...)
    //     - Add dummy ALUT and Config accounts to genesis config initial accounts
    // Genesis Hash -> Root of context blockhash queue

    // var batch_account_cache = BatchAccountCache{};
    // var sysvar_cache = SysvarCache{};
    // const environment = TransactionExecutionEnvironment{
    //     .ancestors = undefined,
    //     .feature_set = &feature_set,
    //     .status_cache = undefined,
    //     .sysvar_cache = undefined,
    //     .rent_collector = undefined,
    //     .blockhash_queue = undefined,
    //     .epoch_stakes = undefined,

    //     .max_age = undefined,
    //     .last_blockhash = undefined,
    //     .next_durable_nonce = undefined,
    //     .next_lamports_per_signature = undefined,
    //     .last_lamports_per_signature = undefined,
    //     .lamports_per_signature = undefined,
    // };

    // const config = TransactionExecutionConfig{
    //     .log = true,
    //     .log_messages_byte_limit = null,
    //     // .account_overrides: None,
    //     // .compute_budget: bank.compute_budget(),
    //     // .log_messages_bytes_limit: None,
    //     // .limit_to_load_programs: true,
    //     // .recording_config,
    //     // .transaction_account_lock_limit: None,
    //     // .check_program_modification_slot: false,
    // };

    // const runtime_transaction = RuntimeTransaction{
    //     .signature_count = undefined,
    //     .fee_payer = undefined,
    //     .msg_hash = msg_hash,
    //     .recent_blockhash = sanitized_transaction.msg.recent_blockhash,
    //     .instruction_infos = undefined,
    //     .accounts = undefined,
    // };

    // const result = try loadAndExecuteTransaction(
    //     allocator,
    //     &runtime_transaction,
    //     &batch_account_cache,
    //     &environment,
    //     &config,
    // );

    // switch (result) {
    //     .ok => |transaction| {
    //         _ = transaction;
    //         // let is_ok = match txn {
    //         //     ProcessedTransaction::Executed(executed_tx) => {
    //         //         executed_tx.execution_details.status.is_ok()
    //         //     }
    //         //     ProcessedTransaction::FeesOnly(_) => false,
    //         // };

    //         // let loaded_accounts_data_size = match txn {
    //         //     ProcessedTransaction::Executed(executed_tx) => {
    //         //         executed_tx.loaded_transaction.loaded_accounts_data_size
    //         //     }
    //         //     ProcessedTransaction::FeesOnly(fees_only_tx) => {
    //         //         fees_only_tx.rollback_accounts.data_size() as u32
    //         //     }
    //         // };

    //         // let (status, instr_err, custom_err, instr_err_idx) =
    //         //     match txn.status().as_ref().map_err(transaction_error_to_err_nums) {
    //         //         Ok(_) => (0, 0, 0, 0),
    //         //         Err((status, instr_err, custom_err, instr_err_idx)) => {
    //         //             // Set custom err to 0 if the failing instruction is a precompile
    //         //             let custom_err_ret = sanitized_message
    //         //                 .instructions()
    //         //                 .get(instr_err_idx as usize)
    //         //                 .and_then(|instr| {
    //         //                     sanitized_message
    //         //                         .account_keys()
    //         //                         .get(instr.program_id_index as usize)
    //         //                         .map(|program_id| {
    //         //                             if get_precompile(program_id, |_| true).is_some() {
    //         //                                 0
    //         //                             } else {
    //         //                                 custom_err
    //         //                             }
    //         //                         })
    //         //                 })
    //         //                 .unwrap_or(custom_err);
    //         //             (status, instr_err, custom_err_ret, instr_err_idx)
    //         //         }
    //         //     };
    //         // let rent = match txn {
    //         //     ProcessedTransaction::Executed(executed_tx) => executed_tx.loaded_transaction.rent,
    //         //     ProcessedTransaction::FeesOnly(_) => 0,
    //         // };
    //         // let resulting_state: Option<ResultingState> = match txn {
    //         //     ProcessedTransaction::Executed(executed_tx) => {
    //         //         Some(executed_tx.loaded_transaction.clone().into())
    //         //     }
    //         //     ProcessedTransaction::FeesOnly(tx) => {
    //         //         let mut accounts = Vec::with_capacity(tx.rollback_accounts.count());
    //         //         collect_accounts_for_failed_tx(
    //         //             &mut accounts,
    //         //             &mut None,
    //         //             sanitized_message,
    //         //             None,
    //         //             &tx.rollback_accounts,
    //         //         );
    //         //         Some(ResultingState {
    //         //             acct_states: accounts
    //         //                 .iter()
    //         //                 .map(|&(pubkey, acct)| (*pubkey, acct.clone()).into())
    //         //                 .collect(),
    //         //             rent_debits: vec![],
    //         //             transaction_rent: 0,
    //         //         })
    //         //     }
    //         // };
    //         // let executed_units = match txn {
    //         //     ProcessedTransaction::Executed(executed_tx) => {
    //         //         executed_tx.execution_details.executed_units
    //         //     }
    //         //     ProcessedTransaction::FeesOnly(_) => 0,
    //         // };
    //         // let return_data = match txn {
    //         //     ProcessedTransaction::Executed(executed_tx) => executed_tx
    //         //         .execution_details
    //         //         .return_data
    //         //         .as_ref()
    //         //         .map(|info| info.clone().data)
    //         //         .unwrap_or_default(),
    //         //     ProcessedTransaction::FeesOnly(_) => vec![],
    //         // };
    //         // (
    //         //     is_ok,
    //         //     false,
    //         //     status,
    //         //     instr_err,
    //         //     instr_err_idx,
    //         //     custom_err,
    //         //     executed_units,
    //         //     return_data,
    //         //     Some(txn.fee_details()),
    //         //     rent,
    //         //     loaded_accounts_data_size,
    //         //     resulting_state,
    //         // )
    //     },
    //     .err => |err| {
    //         _ = err;
    //         // let (status, instr_err, custom_err, instr_err_idx) =
    //         //     transaction_error_to_err_nums(transaction_error);
    //         // (
    //         //     false,
    //         //     true,
    //         //     status,
    //         //     instr_err,
    //         //     instr_err_idx,
    //         //     custom_err,
    //         //     0,
    //         //     vec![],
    //         //     None,
    //         //     0,
    //         //     0,
    //         //     None,
    //         // )
    //     },
    // }

    return .{};
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
