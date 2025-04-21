const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const utils = @import("utils.zig");

const executor = sig.runtime.executor;
const sysvar = sig.runtime.sysvar;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;

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

    // printPbInstrContext(ctx) catch |err| {
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

fn executeInstruction(allocator: std.mem.Allocator, pb_instr_ctx: pb.InstrContext, emit_logs: bool) !pb.InstrEffects {
    const ec, const sc, const tc = try utils.createExecutionContexts(
        allocator,
        pb_instr_ctx,
        emit_logs,
    );
    defer {
        ec.deinit();
        allocator.destroy(ec);
        sc.deinit();
        allocator.destroy(sc);
        tc.deinit();
        allocator.destroy(tc);
    }

    if (pb_instr_ctx.program_id.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
    const instr_info = try utils.createInstructionInfo(
        allocator,
        tc,
        .{ .data = pb_instr_ctx.program_id.getSlice()[0..Pubkey.SIZE].* },
        pb_instr_ctx.data.getSlice(),
        pb_instr_ctx.instr_accounts.items,
    );
    defer instr_info.deinit(allocator);

    var result: ?InstructionError = null;
    executor.executeInstruction(
        allocator,
        tc,
        instr_info,
    ) catch |err| {
        switch (err) {
            error.OutOfMemory => return err,
            else => |e| result = e,
        }
    };

    if (tc.log_collector) |log_collector| {
        std.debug.print("Execution Logs:\n", .{});
        for (log_collector.collect(), 1..) |msg, index| {
            std.debug.print("    {}: {s}\n", .{ index, msg });
        }
    }

    return utils.createInstrEffects(
        allocator,
        tc,
        result,
    );
}
