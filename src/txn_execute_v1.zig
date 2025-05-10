const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const utils = @import("utils.zig");

const sysvar = sig.runtime.sysvar;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;

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

fn executeTxnContext(allocator: std.mem.Allocator, pb_txn_ctx: pb.TxnContext, emit_logs: bool) !pb.TxnResult {
    // const features = try utils.createFeatureSet(allocator, pb_txn_ctx.epoch_ctx.?.features);
    _ = emit_logs;

    // const result = executor.executeTransactionBatch();

    const msg_hash, const transaction = try parseSanitizedTransaction(
        allocator,
        pb_txn_ctx.tx.?,
    );
    transaction.deinit(allocator);
    _ = msg_hash;

    // bank.verify_transaction(...)
    // transaction.verify() catch |err| {
    //     _ = err;
    // };

    return pb.TxnResult{
        .executed = false,
        .sanitization_error = false,
        .resulting_state = .{
            .acct_states = std.ArrayList(pb.AcctState).init(allocator),
            .rent_debits = std.ArrayList(pb.RentDebits).init(allocator),
            .transaction_rent = 0,
        },
        .rent = 0,
        .is_ok = false,
        .status = 0,
        .instruction_error = 0,
        .instruction_error_index = 0,
        .custom_error = 0,
        .return_data = .Empty,
        .executed_units = 0,
        .fee_details = null,
    };
}

pub const TransactionWithMeta = struct {
    transaction: Transaction,
    loaded_addresses: []const Pubkey,
};

pub const TransactionError = error{
    /// An account is already being processed in another transaction in a way
    /// that does not support parallelism
    AccountInUse,

    /// A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference
    /// `Pubkey`s more than once but the message must contain a list with no duplicate keys
    AccountLoadedTwice,

    /// Attempt to debit an account but found no record of a prior credit.
    AccountNotFound,

    /// Attempt to load a program that does not exist
    ProgramAccountNotFound,

    /// The from `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction
    InsufficientFundsForFee,

    /// This account may not be used to pay transaction fees
    InvalidAccountForFee,

    /// The bank has seen this transaction before. This can occur under normal operation
    /// when a UDP packet is duplicated, as a user error from a client not updating
    /// its `recent_blockhash`, or as a double-spend attack.
    AlreadyProcessed,

    /// The bank has not seen the given `recent_blockhash` or the transaction is too old and
    /// the `recent_blockhash` has been discarded.
    BlockhashNotFound,

    /// An error occurred while processing an instruction. The first element of the tuple
    /// indicates the instruction index in which the error occurred.
    InstructionError, // struct { instruction_index: u8, err: InstructionError },

    /// Loader call chain is too deep
    CallChainTooDeep,

    /// Transaction requires a fee but has no signature present
    MissingSignatureForFee,

    /// Transaction contains an invalid account reference
    InvalidAccountIndex,

    /// Transaction did not pass signature verification
    SignatureFailure,

    /// This program may not be used for executing instructions
    InvalidProgramForExecution,

    /// Transaction failed to sanitize accounts offsets correctly
    /// implies that account locks are not taken for this TX, and should
    /// not be unlocked.
    SanitizeFailure,

    ClusterMaintenance,

    /// Transaction processing left an account with an outstanding borrowed reference
    AccountBorrowOutstanding,

    /// Transaction would exceed max Block Cost Limit
    WouldExceedMaxBlockCostLimit,

    /// Transaction version is unsupported
    UnsupportedVersion,

    /// Transaction loads a writable account that cannot be written
    InvalidWritableAccount,

    /// Transaction would exceed max account limit within the block
    WouldExceedMaxAccountCostLimit,

    /// Transaction would exceed account data limit within the block
    WouldExceedAccountDataBlockLimit,

    /// Transaction locked too many accounts
    TooManyAccountLocks,

    /// Address lookup table not found
    AddressLookupTableNotFound,

    /// Attempted to lookup addresses from an account owned by the wrong program
    InvalidAddressLookupTableOwner,

    /// Attempted to lookup addresses from an invalid account
    InvalidAddressLookupTableData,

    /// Address table lookup uses an invalid index
    InvalidAddressLookupTableIndex,

    /// Transaction leaves an account with a lower balance than rent-exempt minimum
    InvalidRentPayingAccount,

    /// Transaction would exceed max Vote Cost Limit
    WouldExceedMaxVoteCostLimit,

    /// Transaction would exceed total account data limit
    WouldExceedAccountDataTotalLimit,

    /// Transaction contains a duplicate instruction that is not allowed
    DuplicateInstruction, // u8,

    /// Transaction results in an account with insufficient funds for rent
    InsufficientFundsForRent, // struct { account_index: u8 },

    /// Transaction exceeded max loaded accounts data size cap
    MaxLoadedAccountsDataSizeExceeded,

    /// LoadedAccountsDataSizeLimit set for transaction must be greater than 0.
    InvalidLoadedAccountsDataSizeLimit,

    /// Sanitized transaction differed before/after feature activiation. Needs to be resanitized.
    ResanitizationNeeded,

    /// Program execution is temporarily restricted on an account.
    ProgramExecutionTemporarilyRestricted, // struct { account_index: u8 },
};

pub fn intFromTransactionError(err: TransactionError) u32 {
    return switch (err) {
        error.AccountInUse => 1,
        error.AccountLoadedTwice => 2,
        error.AccountNotFound => 3,
        error.ProgramAccountNotFound => 4,
        error.InsufficientFundsForFee => 5,
        error.InvalidAccountForFee => 6,
        error.AlreadyProcessed => 7,
        error.BlockhashNotFound => 8,
        error.InstructionError => 9,
        error.CallChainTooDeep => 10,
        error.MissingSignatureForFee => 11,
        error.InvalidAccountIndex => 12,
        error.SignatureFailure => 13,
        error.InvalidProgramForExecution => 14,
        error.SanitizeFailure => 15,
        error.ClusterMaintenance => 16,
        error.AccountBorrowOutstanding => 17,
        error.WouldExceedMaxBlockCostLimit => 18,
        error.UnsupportedVersion => 19,
        error.InvalidWritableAccount => 21,
        error.WouldExceedMaxAccountCostLimit => 22,
        error.WouldExceedAccountDataBlockLimit => 23,
        error.TooManyAccountLocks => 24,
        error.AddressLookupTableNotFound => 25,
        error.InvalidAddressLookupTableOwner => 26,
        error.InvalidAddressLookupTableData => 27,
        error.InvalidAddressLookupTableIndex => 28,
        error.InvalidRentPayingAccount => 29,
        error.WouldExceedMaxVoteCostLimit => 30,
        error.WouldExceedAccountDataTotalLimit => 31,
        error.DuplicateInstruction => 32,
        error.InsufficientFundsForRent => 33,
        error.MaxLoadedAccountsDataSizeExceeded => 34,
        error.InvalidLoadedAccountsDataSizeLimit => 35,
        error.ResanitizationNeeded => 36,
        error.ProgramExecutionTemporarilyRestricted => 37,
    };
}

const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const Transaction = sig.core.Transaction;
const TransactionVersion = sig.core.transaction.TransactionVersion;
const TransactionMessage = sig.core.transaction.TransactionMessage;
const TransactionInstruction = sig.core.transaction.TransactionInstruction;
const TransactionAddressLookup = sig.core.transaction.TransactionAddressLookup;

fn parseSanitizedTransaction(
    allocator: std.mem.Allocator,
    transaction: pb.SanitizedTransaction,
) !struct { Hash, Transaction } {
    const signatures = try allocator.alloc(Signature, transaction.signatures.items.len);
    for (signatures, transaction.signatures.items) |*signature, pb_signature|
        signature.* = .{ .data = pb_signature.getSlice()[0..Signature.SIZE].* };
    const message_hash = Hash{ .data = transaction.message_hash.getSlice()[0..Hash.SIZE].* };
    const version, const message = try parseTransactionMesssage(
        allocator,
        transaction.message.?,
    );
    return .{
        message_hash,
        .{
            .signatures = signatures,
            .version = version,
            .msg = message,
        },
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
