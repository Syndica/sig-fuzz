const effects = @import("effects.zig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const setup = @import("setup.zig");
const sig = @import("sig");
const std = @import("std");

const executor = sig.runtime.executor;
const sysvar = sig.runtime.sysvar;

const InstructionError = sig.core.instruction.InstructionError;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;

// Loader imports
const bpf_loader = sig.runtime.program.bpf_loader;
const program_loader = sig.runtime.program_loader;
const ComputeBudget = sig.runtime.ComputeBudget;
const Hash = sig.core.Hash;
const ProgramMap = sig.runtime.program_loader.ProgramMap;
const VmEnvironment = sig.vm.Environment;
const EpochStakes = sig.core.stake.EpochStakes;
const LogCollector = sig.runtime.LogCollector;
const TransactionContextAccount = sig.runtime.transaction_context.TransactionContextAccount;

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

fn executeInstruction(
    allocator: std.mem.Allocator,
    instruction_context: pb.InstrContext,
    emit_logs: bool,
) !pb.InstrEffects {
    errdefer |err| {
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
        std.debug.print("executeInstruction: {s}\n", .{@errorName(err)});
    }

    const accounts = try setup.loadAccounts(allocator, instruction_context);
    defer {
        for (accounts.values()) |acc| allocator.free(acc.data);
        var accs = accounts;
        accs.deinit(allocator);
    }

    const feature_set = try setup.loadFeatureSet(allocator, instruction_context);
    defer feature_set.deinit(allocator);

    const epoch_stakes = try EpochStakes.initEmpty(allocator);
    defer epoch_stakes.deinit(allocator);

    const sysvar_cache = try setup.loadSysvarCache(allocator, instruction_context);
    defer sysvar_cache.deinit(allocator);

    const compute_budget = ComputeBudget.default(instruction_context.cu_avail);

    const vm_environment = try VmEnvironment.initV1(
        allocator,
        &feature_set,
        &compute_budget,
        false,
        false,
    );
    defer vm_environment.deinit(allocator);

    const clock = try sysvar_cache.get(sysvar.Clock);
    const epoch_schedule = try sysvar_cache.get(sysvar.EpochSchedule);
    const rent = try sysvar_cache.get(sysvar.Rent);

    const maybe_recent_blockhashes = sysvar_cache.get(sysvar.RecentBlockhashes) catch null;
    const maybe_last_entry = if (maybe_recent_blockhashes) |rb| rb.last() else null;
    const blockhash, const lamports_per_signature = if (maybe_last_entry) |entry|
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

    var program_map = ProgramMap{};
    defer {
        for (program_map.values()) |v| v.deinit(allocator);
        program_map.deinit(allocator);
    }

    for (accounts.keys(), accounts.values()) |pubkey, account| {
        if (!pubkey.equals(&bpf_loader.v1.ID) and
            !pubkey.equals(&bpf_loader.v2.ID) and
            !pubkey.equals(&bpf_loader.v3.ID) and
            !pubkey.equals(&bpf_loader.v4.ID)) continue;

        try program_map.put(allocator, pubkey, try program_loader.loadProgram(
            allocator,
            &account,
            &accounts,
            &vm_environment,
            clock.slot,
        ));
    }

    const transaction_context_accounts = try allocator.alloc(
        TransactionContextAccount,
        instruction_context.accounts.items.len,
    );
    for (instruction_context.accounts.items, 0..) |account, i| {
        const pubkey = try setup.parsePubkey(account.address);
        transaction_context_accounts[i] = TransactionContextAccount{
            .pubkey = pubkey,
            .account = accounts.getPtr(pubkey).?,
        };
    }

    var transaction_context = TransactionContext{
        .allocator = allocator,
        .feature_set = &feature_set,
        .epoch_stakes = &epoch_stakes,
        .sysvar_cache = &sysvar_cache,
        .vm_environment = &vm_environment,
        .next_vm_environment = null,
        .program_map = &program_map,
        .accounts = transaction_context_accounts,
        .compute_meter = compute_budget.compute_unit_limit,
        .compute_budget = compute_budget,
        .log_collector = LogCollector.default(),
        .prev_blockhash = blockhash,
        .prev_lamports_per_signature = lamports_per_signature,
        .rent = rent,
    };
    defer transaction_context.deinit();

    const instruction_info = try setup.createInstructionInfo(
        allocator,
        &transaction_context,
        instruction_context,
    );
    defer instruction_info.deinit(allocator);

    var result: ?InstructionError = null;
    executor.executeInstruction(
        allocator,
        &transaction_context,
        instruction_info,
    ) catch |err| {
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| result = e,
        }
    };

    if (emit_logs) {
        std.debug.print("Execution Logs:\n", .{});
        for (transaction_context.log_collector.?.collect(), 1..) |msg, index| {
            std.debug.print("    {}: {s}\n", .{ index, msg });
        }
    }

    _ = epoch_schedule;

    return effects.createInstrEffects(
        allocator,
        &transaction_context,
        result,
    );
}
