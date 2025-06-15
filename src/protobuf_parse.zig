const sig = @import("sig");
const std = @import("std");
const protobuf = @import("protobuf");

const Pubkey = sig.core.Pubkey;
const ManagedString = protobuf.ManagedString;

pub fn parsePubkey(
    address: ManagedString,
) !Pubkey {
    if (address.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
    return .{ .data = address.getSlice()[0..Pubkey.SIZE].* };
}
