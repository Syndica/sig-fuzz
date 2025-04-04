const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");

const ManagedString = @import("protobuf").ManagedString;

const features = sig.runtime.features;
const executor = sig.runtime.executor;

const InstructionError = sig.core.instruction.InstructionError;
const InstructionInfo = sig.runtime.instruction_info.InstructionInfo;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;
const TransactionContextAccount = sig.runtime.transaction_context.TransactionContextAccount;

const Pubkey = sig.core.Pubkey;

fn printPbInstrContext(ctx: pb.InstrContext) !void {
    var buffer = [_]u8{0} ** (1024 * 1024);
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    writer.writeAll("InstrContext {") catch return;
    std.fmt.format(writer, "\n\tprogram_id: {any}", .{ctx.program_id.getSlice()}) catch return;
    writer.writeAll(",\n\taccounts: [") catch return;
    for (ctx.accounts.items) |acc| {
        writer.writeAll("\n\t\tAcctState {") catch return;
        std.fmt.format(writer, "\n\t\t\taddress: {any}", .{acc.address.getSlice()}) catch return;
        std.fmt.format(writer, ",\n\t\t\tlamports: {d}", .{acc.lamports}) catch return;
        std.fmt.format(writer, ",\n\t\t\tdata: {any}", .{acc.data.getSlice()}) catch return;
        std.fmt.format(writer, ",\n\t\t\texecutable: {}", .{acc.executable}) catch return;
        std.fmt.format(writer, ",\n\t\t\trent_epoch: {}", .{acc.rent_epoch}) catch return;
        std.fmt.format(writer, ",\n\t\t\towner: {any}", .{acc.owner.getSlice()}) catch return;
        writer.writeAll("\n\t\t},\n") catch return;
    }
    writer.writeAll("\t],\n\tinstr_accounts: [") catch return;
    for (ctx.instr_accounts.items) |acc| {
        writer.writeAll("\n\t\tInstrAcct {") catch return;
        std.fmt.format(writer, "\n\t\t\tindex: {}", .{acc.index}) catch return;
        std.fmt.format(writer, ",\n\t\t\tis_signer: {}", .{acc.is_signer}) catch return;
        std.fmt.format(writer, ",\n\t\t\tis_writable: {}", .{acc.is_writable}) catch return;
        writer.writeAll("\n\t\t},\n") catch return;
    }
    std.fmt.format(writer, "\t],\n\tdata: {any}", .{ctx.data.getSlice()}) catch return;
    std.fmt.format(writer, ",\n\tcu_avail: {d}", .{ctx.cu_avail}) catch return;
    writer.writeAll(",\n}\n") catch return;
    std.debug.print("{s}", .{writer.context.getWritten()});
}

fn printPbInstrEffects(effects: pb.InstrEffects) !void {
    var buffer = [_]u8{0} ** (1024 * 1024);
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    writer.writeAll("InstrEffects {") catch return;
    std.fmt.format(writer, "\n\tresult: {d}", .{effects.result}) catch return;
    std.fmt.format(writer, ",\n\tcustom_err: {d}", .{effects.custom_err}) catch return;
    writer.writeAll(",\n\tmodified_accounts: [") catch return;
    for (effects.modified_accounts.items) |acc| {
        writer.writeAll("\n\t\tAcctState {") catch return;
        std.fmt.format(writer, "\n\t\t\taddress: {any}", .{acc.address.getSlice()}) catch return;
        std.fmt.format(writer, ",\n\t\t\tlamports: {d}", .{acc.lamports}) catch return;
        std.fmt.format(writer, ",\n\t\t\tdata: {any}", .{acc.data.getSlice()}) catch return;
        std.fmt.format(writer, ",\n\t\t\texecutable: {}", .{acc.executable}) catch return;
        std.fmt.format(writer, ",\n\t\t\trent_epoch: {}", .{acc.rent_epoch}) catch return;
        std.fmt.format(writer, ",\n\t\t\towner: {any}", .{acc.owner.getSlice()}) catch return;
        writer.writeAll("\n\t\t},\n") catch return;
    }
    writer.writeAll("\t],") catch return;
    std.fmt.format(writer, ",\n\tcu_avail: {d}", .{effects.cu_avail}) catch return;
    std.fmt.format(writer, ",\n\treturn_data: {any}", .{effects.return_data.getSlice()}) catch return;
    writer.writeAll("\n}\n") catch return;
    std.debug.print("{s}", .{writer.context.getWritten()});
}
