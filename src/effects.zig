const pbs = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");

const ManagedString = @import("protobuf").ManagedString;

const InstructionError = sig.core.instruction.InstructionError;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;

const intFromInstructionError = sig.core.instruction.intFromInstructionError;

pub fn createInstrEffects(
    allocator: std.mem.Allocator,
    transaction_context: *const TransactionContext,
    maybe_instruction_error: ?InstructionError,
) !pbs.InstrEffects {
    const result = if (maybe_instruction_error) |err|
        intFromInstructionError(err)
    else
        0;

    const modified_accounts = try getModifiedAccounts(
        allocator,
        transaction_context,
    );

    const return_data = try ManagedString.copy(
        transaction_context.return_data.data.constSlice(),
        allocator,
    );

    return pbs.InstrEffects{
        .result = result,
        .custom_err = transaction_context.custom_error orelse 0,
        .modified_accounts = modified_accounts,
        .cu_avail = transaction_context.compute_meter,
        .return_data = return_data,
    };
}

fn getModifiedAccounts(
    allocator: std.mem.Allocator,
    transaction_context: *const TransactionContext,
) !std.ArrayList(pbs.AcctState) {
    var accounts = std.ArrayList(pbs.AcctState).init(allocator);
    errdefer accounts.deinit();

    for (transaction_context.accounts) |acc| {
        try accounts.append(.{
            .address = try ManagedString.copy(
                &acc.pubkey.data,
                allocator,
            ),
            .lamports = acc.account.lamports,
            .data = try ManagedString.copy(
                acc.account.data,
                allocator,
            ),
            .executable = acc.account.executable,
            .rent_epoch = acc.account.rent_epoch,
            .owner = try ManagedString.copy(
                &acc.account.owner.data,
                allocator,
            ),
        });
    }

    return accounts;
}
