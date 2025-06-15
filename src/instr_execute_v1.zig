const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
// const utils = @import("utils.zig");
const protobuf_parse = @import("protobuf_parse.zig");

const executor = sig.runtime.executor;
const sysvar = sig.runtime.sysvar;
const features = sig.runtime.features;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;
const BatchAccounts = sig.runtime.account_loader.BatchAccountCache;

const EMIT_LOGS = false;

/// [fd] https://github.com/firedancer-io/firedancer/blob/0ad2143a9960b7daa5eb594367835d0cbae25657/src/flamenco/runtime/tests/fd_exec_sol_compat.c#L591
/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/98f939ba8afcb1b7a5af4316c6085f92111b62a7/src/lib.rs#L1043
export fn sol_compat_instr_execute_v1(
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
    var pb_instr_ctx = pb.InstrContext.decode(
        in_slice,
        decode_arena.allocator(),
    ) catch |err| {
        std.debug.print("pb.InstrContext.decode: {s}\n", .{@errorName(err)});
        return 0;
    };
    defer pb_instr_ctx.deinit();

    // utils.printPbInstrContext(pb_instr_ctx) catch |err| {
    //     std.debug.print("printPbInstrContext: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result = executeInstruction(allocator, pb_instr_ctx, EMIT_LOGS) catch |err| {
        std.debug.print("executeInstruction: {s}\n", .{@errorName(err)});
        return 0;
    };

    // printPbInstrEffects(result) catch |err| {
    //     std.debug.print("printPbInstrEffects: {s}\n", .{@errorName(err)});
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

const AccountSharedData = sig.runtime.AccountSharedData;
const bpf_loader = sig.runtime.program.bpf_loader;

/// Load accounts for instruction harness.
/// [agave] https://github.com/firedancer-io/solfuzz-agave/blob/11c04e7e6a1edc014c2f7899311b0ca8e49f9d0c/src/lib.rs#L765-L793
fn loadAccounts(
    allocator: std.mem.Allocator,
    pb_instr_ctx: pb.InstrContext,
) !std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData) {
    const program_pubkey = try protobuf_parse.parsePubkey(pb_instr_ctx.program_id);

    var accounts = std.AutoArrayHashMapUnmanaged(
        Pubkey,
        AccountSharedData,
    ){};
    errdefer {
        for (accounts.values()) |acc| allocator.free(acc.data);
        accounts.deinit(allocator);
    }

    for (pb_instr_ctx.accounts.items) |account| {
        const pubkey = try protobuf_parse.parsePubkey(account.address);

        // If duplicate accounts are present, this account loader must be adjusted.
        if (accounts.contains(pubkey)) return error.DuplicateAccount;

        // TODO: May need to mannually override the owner and executable for bpf conformance
        // [agave] https://github.com/firedancer-io/solfuzz-agave/blob/11c04e7e6a1edc014c2f7899311b0ca8e49f9d0c/src/lib.rs#L776-L791
        // const owner, const executable = if (pubkey.equals(&program_pubkey))
        //     .{ bpf_loader.v3.ID, true }
        // else
        //     .{ try protobuf_parse.parsePubkey(account.owner), account.executable };
        const owner = try protobuf_parse.parsePubkey(account.owner);
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

const FeatureSet = sig.runtime.FeatureSet;

fn loadFeatureSet(allocator: std.mem.Allocator, pb_instr_ctx: pb.InstrContext) !FeatureSet {
    const maybe_pb_features = if (pb_instr_ctx.epoch_context) |epoch_ctx|
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

const SysvarCache = sig.runtime.SysvarCache;

fn loadSysvarCache(
    allocator: std.mem.Allocator,
    pb_instr_ctx: pb.InstrContext,
) !SysvarCache {
    _ = allocator;
    _ = pb_instr_ctx;
    @panic("loadSysvarCache not implemented");
}

const program_loader = sig.runtime.program_loader;
const ComputeBudget = sig.runtime.ComputeBudget;
const Hash = sig.core.Hash;
const LoadedProgram = sig.runtime.program_loader.LoadedProgram;

fn executeInstruction(allocator: std.mem.Allocator, pb_instr_ctx: pb.InstrContext, emit_logs: bool) !pb.InstrEffects {
    const accounts = try loadAccounts(allocator, pb_instr_ctx);
    const feature_set = try loadFeatureSet(allocator, pb_instr_ctx);
    const sysvar_cache = try loadSysvarCache(allocator, pb_instr_ctx);
    const compute_budget = ComputeBudget.default(pb_instr_ctx.cu_avail);
    const loader_v1 = try sig.vm.syscalls.register(allocator, &feature_set, false);
    const config_v1 = sig.vm.Config.initV1(feature_set, compute_budget, false, false);

    const clock = try sysvar_cache.get(sysvar.Clock);
    const epoch_schedule = try sysvar_cache.get(sysvar.EpochSchedule);
    const rent = try sysvar_cache.get(sysvar.Rent);
    const recent_blockhashes = try sysvar_cache.get(sysvar.RecentBlockhashes);

    const blockhash, const lamports_per_signature = if (recent_blockhashes.last()) |entry|
        .{ entry.blockhash, entry.fee_calculator.lamports_per_signature }
    else
        .{ Hash.ZEROES, 0 };

    if (rent.lamports_per_byte_year > std.math.maxInt(u32) or
        rent.exemption_threshold > 999.0 or
        rent.exemption_threshold < 0.0 or
        rent.burn_percent > 100)
    {
        return error.InvalidRent;
    }

    var program_map = std.AutoArrayHashMapUnmanaged(Pubkey, LoadedProgram){};
    for (accounts.keys(), accounts.values()) |pubkey, account| {
        if (!pubkey.equals(&bpf_loader.v1.ID) and
            !pubkey.equals(&bpf_loader.v2.ID) and
            !pubkey.equals(&bpf_loader.v3.ID) and
            !pubkey.equals(&bpf_loader.v4.ID)) continue;

        try program_map.put(allocator, pubkey, try program_loader.loadProgram(
            allocator,
            &account,
            &accounts,
            &loader_v1,
            &config_v1,
            clock.slot,
        ));
    }

    _ = emit_logs;
    _ = epoch_schedule;
    _ = blockhash;
    _ = lamports_per_signature;

    return error.Unimplemented;

    // var tc: TransactionContext = undefined;
    // try utils.createTransactionContext(
    //     allocator,
    //     pb_instr_ctx,
    //     .{},
    //     &tc,
    //     &accounts,
    // );
    // defer utils.deinitTransactionContext(allocator, tc);

    // if (pb_instr_ctx.program_id.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
    // const instr_info = try utils.createInstructionInfo(
    //     allocator,
    //     &tc,
    //     .{ .data = pb_instr_ctx.program_id.getSlice()[0..Pubkey.SIZE].* },
    //     pb_instr_ctx.data.getSlice(),
    //     pb_instr_ctx.instr_accounts.items,
    // );
    // defer instr_info.deinit(allocator);

    // var result: ?InstructionError = null;
    // executor.executeInstruction(
    //     allocator,
    //     &tc,
    //     instr_info,
    // ) catch |err| {
    //     switch (err) {
    //         error.OutOfMemory => return err,
    //         else => |e| result = e,
    //     }
    // };

    // if (emit_logs) {
    //     std.debug.print("Execution Logs:\n", .{});
    //     for (tc.log_collector.?.collect(), 1..) |msg, index| {
    //         std.debug.print("    {}: {s}\n", .{ index, msg });
    //     }
    // }

    // return utils.createInstrEffects(
    //     allocator,
    //     &tc,
    //     result,
    // );
}
