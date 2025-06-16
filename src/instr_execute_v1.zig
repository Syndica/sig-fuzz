const effects = @import("effects.zig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const setup = @import("setup.zig");
const sig = @import("sig");
const std = @import("std");

const executor = sig.runtime.executor;

const InstructionError = sig.core.instruction.InstructionError;
const TransactionContext = sig.runtime.TransactionContext;

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
    var instruction_context = try pb.InstrContext.decode(
        in_slice,
        decode_arena.allocator(),
    );
    defer instruction_context.deinit();

    // utils.printPbInstrContext(pb_instr_ctx) catch |err| {
    //     std.debug.print("printPbInstrContext: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result = executeInstruction(allocator, &instruction_context, EMIT_LOGS) catch |err| {
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
    instruction_context: *const pb.InstrContext,
    emit_logs: bool,
) !pb.InstrEffects {
    const loaded_accounts = try setup.loadAccounts(
        allocator,
        instruction_context,
    );
    defer {
        for (loaded_accounts.values()) |acc| allocator.free(acc.data);
        var accs = loaded_accounts;
        accs.deinit(allocator);
    }

    var transaction_context: TransactionContext = undefined;
    try setup.createTransactionContext(
        allocator,
        &transaction_context,
        &loaded_accounts,
        instruction_context,
        null,
    );
    defer setup.deinitTransactionContext(allocator, transaction_context);

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

    return effects.createInstrEffects(
        allocator,
        &transaction_context,
        result,
    );
}
