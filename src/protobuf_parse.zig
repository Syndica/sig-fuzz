const sig = @import("sig");
const std = @import("std");
const protobuf = @import("protobuf");

const ManagedString = protobuf.ManagedString;

pub fn parsePubkey(
    address: ManagedString,
) !sig.Pubkey {
    if (address.getSlice().len != sig.Pubkey.SIZE) return error.OutOfBounds;
    return .{ .data = address.getSlice()[0..sig.Pubkey.SIZE].* };
}
