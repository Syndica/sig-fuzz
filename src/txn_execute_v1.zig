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
        std.debug.print("pb.InstrContext.decode: {s}\n", .{@errorName(err)});
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

// pub const executor = struct {
//     pub const AccountsDb = sig.accounts_db.AccountsDB;
//     pub const Transaction = sig.core.Transaction;
//     pub const FeatureSet = sig.runtime.FeatureSet;
//     pub const ComputeBudget = sig.runtime.ComputeBudget;
//     pub const RentCollector = sig.runtime.rent_collector.RentCollector;
//     pub const SysvarCache = sig.runtime.sysvar_cache.SysvarCache;
//     pub const Ancestors = sig.accounts_db.snapshots.Ancestors;
//     pub const StatusCache = sig.accounts_db.snapshots.StatusCache;
//     pub const BlockhashQueue = sig.accounts_db.snapshots.BlockhashQueue;

//     pub const BuiltinProgramIds = std.AutoArrayHashMap(Pubkey, void);
//     pub const ProgramCache = struct {};
//     pub const ExecuteBatchResult = struct {};
//     pub const FeeStructure = struct {};

//     pub fn executeTransactionBatch(
//         allocator: std.mem.Allocator,
//         slot: u64,
//         batch: []const Transaction,
//         fee_collector: Pubkey,
//         feature_set: *const FeatureSet,
//         fee_structure: *const FeeStructure,
//         compute_budget: *const ComputeBudget,
//         blockhash_queue: *const BlockhashQueue,
//         builtin_program_ids: *BuiltinProgramIds,
//         sysvar_cache: *SysvarCache,
//         program_cache: *ProgramCache,
//         status_cache: *StatusCache,
//     ) !ExecuteBatchResult {}
// };

fn executeTxnContext(allocator: std.mem.Allocator, pb_txn_ctx: pb.TxnContext, emit_logs: bool) !pb.TxnResult {
    // const features = try utils.createFeatureSet(allocator, pb_txn_ctx.epoch_ctx.?.features);
    _ = allocator;
    _ = pb_txn_ctx;
    _ = emit_logs;

    // const result = executor.executeTransactionBatch();

    return error.Unimplemented;
}
