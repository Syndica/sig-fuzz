const std = @import("std");

comptime {
    _ = @import("elf.zig");
    _ = @import("shred_parse.zig");
    _ = @import("instr_execute_v1.zig");
    _ = @import("vm_interp.zig");
    _ = @import("vm_syscall_execute_v1.zig");
}

pub const std_options: std.Options = .{
    .log_level = .warn,
};

export fn sol_compat_init(log_level: i32) void {
    _ = log_level;
}
export fn sol_compat_fini() void {}

const SolCompatFeatures = extern struct {
    struct_size: u64,
    hardcoded_features: ?[*]const u64,
    hardcoded_features_len: u64,
    supported_features: ?[*]const u64,
    supported_features_len: u64,
};

const HARDCODED_FEATURES = [_]u64{};

const SUPPORTED_FEATURES = [_]u64{
    0x2577305f7cc65fe7,
    0x7095d36bc836da32,
    0x8b990f20829df9b8,
    0x47e18859d27e3aa3,
    0xe7571f86aa06f160,
    0xd924059c5749c4c1,
    0x159967bd804742c2,
    0x1d41fee249e6cc37,
    0xa6d8eedf48633be2,
    0x65b79c7f3e7441b3,
    0x51949af2871c7c99,
    0xfaa4899494a281ec,
    0x30ab53221abfd626,
    0x4ab8b2b10003ad50,
    0xe8f97382b03240a1,
    0xe994a4b8eeea84f4,
    0x10a1e092dd7f1573,
    0xc6eb259e772475c8,
    0xfba69c4970d7ad9d,
    0xb5b508c4a6313e99,
    0xabff1d2abfa0c4bc,
    0xa952e12150121a45,
    0x62885c46a116e1d6,
    0xd5830390d36ee60e,
    0xff00aac3cfaafcfe,
    0x6d22c4ce75df6f0b,
    0xd544636252beca0e,
    0x4b1e586fc635dc65,
    0x7ca46573f5a27822,
    0x1a6958db2ff09870,
    0x15766ba9a908483c,
    0x4b5c55d9eaf96eee,
    0xf162e5606a687206,
    0x35dd1ed4b9d19b9b,
    0x30bf137796030f21,
    0xa5ece90c9d468a56,
    0xf1084016618f3ec0,
    0x92be3cd65cb3e2c3,
    0xbd02d2f51146c257,
    0xfcd1ef949cf886f1,
    0xee2a44e1f54f5e5a,
    0xc548c6b11d33172f,
    0xf1d277eeafe62810,
    0xbdb86acdf94382f4,
    0xa7654aedafa0a2a4,
    0x3ab28ef5d5cf7ca6,
    0x9021d56a2c13c119,
    0x2b8134b3adacd035,
    0x1cec25430fa6229f,
    0x4c8dc4f1e61649dd,
    0xe79e065446760ac3,
    0x7a63cd44b42c0b82,
    0x168bc52564a1181f,
    0xe4f010aefd867566,
    0xa85d651d8da169c6,
    0x7bc99a080444c8d9,
    0x0203237cf1901d09,
    0x7e8f67ed363c31a6,
    0xf28b599c33eda89f,
    0xffed385aa352ef27,
    0x06adecee02a12019,
    0xd79987a3abf61d2d,
    0xd56fc1708dc98c13,
    0x317a863da11d0a8d,
    0x96ac475392d395d8,
    0x9479e273205da38a,
    0xd89ef3a8c30d1ba7,
    0xe2276359bb5e6007,
    0xf02385c19b529325,
    0xf1762ae45609273b,
    0xbff452bfed793f26,
    0xe505bd1df7964bfc,
    0x80288c645d23a80b,
    0x499ab78fe1142d63,
    0x9f43d6cae453a7e5,
    0x562f76c6d74c31ea,
    0xf70ae71daf8a1bd6,
    0x7f6371bf4a56a106,
    0x3ca58e628f040b68,
    0x7e787d5c6d662d23,
    0xffc496b47872d42f,
    0x2bf29bf13f0e1d5d,
    0x073a0a7d3f570b55,
    0x4d6ae02c256bdf10,
    0x5bf898a97b29c67f,
    0xe8f10f26141749dd,
    0xe02ac5f848d395d8,
    0x7b285d0430faf2fc,
    0xf3ee1d3b0fcfec0c,
    0xfc0fb9c317b6c16b,
    0x562011e7dbadd982,
    0x5458f71cc7cd31e0,
    0x606490c1431ae278,
    0xd151c2100e71455b,
    0x2fdc300bd0720815,
    0x5a5c2eab595223bf,
    0xdda7e56980356920,
    0xc358973434287fe8,
    0xe210655c824cfb2f,
    0xc3cc3bdc6eea2eb1,
    0x2758d3af483c6abe,
    0xb0e571b1579c09fc,
    0xcb5d0779751b0c2b,
    0x5795654d01457757,
    0x6799d3fbcc438c0c,
    0x4439548ebff1d6f1,
    0xe5394b6d65186d70,
    0x8f688d4e3ab17a60,
    0xe364c75ced9b53a7,
    0x41b914ee34cb0368,
    0x14a73a8e87cee681,
    0xe21e6fa7a57304e2,
    0x6d1e7092a4aae574,
    0x2ca5833736ba5c69,
    0x855543b1e6e31e10,
    0x204b4907aacbc996,
    0x80f1bedb2c2facaf,
    0x6796bad7d20e8806,
    0xe0724b3421984e49,
    0xada15a4b53efaad4,
    0x41fd0d35fd8339c9,
    0x91b03055f3636ce0,
    0x5b2c24f10d5a1a81,
    0x1728caf9bc767c3f,
    0x819bd0526bd811cb,
    0x0d8a57d3828615b9,
    0xb527e5f5e76ce07b,
    0x2ac194a6a536cee4,
    0xa6862bcb2044252b,
    0x9f4323f726178849,
    0xaaef1edeb6c5bf85,
    0x795c88a20bcb6dfd,
    0x8a8eb9085ca2bb0b,
    0x33e6e44dc3a9cfb2,
    0xc3df53505d0f7aed,
    0x784adb4f1d180869,
    0x71eba1d288ba2bfc,
    0x823d14dd6235f859,
    0xb3f6cd09abba192b,
    0x3a315b1ab012eec3,
    0x500aab8a23ff8b33,
    0xffe35ea7abb29bbb,
    0x8a22c4e80489c387,
    0xce82bcc13c5649fa,
    0x8ff9cf8537529ed8,
    0xd6120d1b80de5fea,
    0xca9ab2701c9aa81b,
    0xeee4f782117a3096,
    0x28b4db1b1a8a9d90,
    0x55d3a0c392cf63e0,
    0x0e7aa95037c5daac, // switch_to_new_elf_parser
    0xe2d13039d5f9c6a6,
    0xcae3ec6191402713,
    0xa6b1a5bbb608b7c9,
    0x50a615bae8ca3874,
    0xda4dd6055b75ae43,
    0x2f51d89fe8ee0500,
    0x61aaf185493a599f,
    0x74326f811fd7d861,
    0x2bd7391d0e103c41,
    0x401b668e4b13b8f9,
    0x74b022574093eeec,
    0x81b8fd99bea25f9b,
    0x3cbf822ccb2eebd4,
    0xe9d32123513c4d0d,
    0x64205286d7935342,
    0x97f912be04ecd673,
    0x4b241cb4c6f3b3b2,
    0x21746beaa849f9d9,
    0x9bb55b5df1c396c5,
    0x6b9b55aefe23036c,
    0xe779d032af3fc8c8,
    0x583989aa9681db6a,
    0xa511cde5058d996f,
    0xa414b36a8ea378a1,
    0x6c49f08f6ae2dad4,
    0x8c2c2963ae9f420c,
    0xcd42326b6c24cb0e,
    0xd17b392feb1e0fe6,
    0x0207866b7b2c7452,
    0x592e701c2ba17409,
    0xbe955088bcb5a209,
    0xfbce25936c716309,
    0x116e31cc55ce7d0b,
    0x8c43e9b9ea49be60,
    0x9b6307ae6da60a0b,
    0xf423d4e1d688cb0e,
    0xa1518043438beb0d,
    0xdb27ab6a4a6379d5,
    0x814079c434b79c66,
    0xfde0b578d38fc5a1,
    0xf711255aedfe2d0d,
    0x81f658d2653a6051,
    0xf1f206f6027db529,
    0x1d15c9469c7c0ca8,
    0xb6edac8134dff06e,
    0x7e4172e5ba362509,
    0x8ba9e9038d9fdcff,
    0xafe148ad652172dd,
    0x91a7af96555ea309,
    0x8e1411a93085cb0e,
    0x0b9047b5bb9ef961,
    0xa5a66405d0ab6309,
    0x81fcbfa0d0f6b105,
    0x2c38e34ff071060d,
    0x829062f252ef5ba8,
    0x1db51f609c8fcd07,
    0xe5937c9dd5edd306,
    0xefc2cb9c2b40f3ff,
    0x408e6a8a269a6ad1,
    0xbec08bda942c5ea5,
    0xf46b1f18665c4236,
    0xa9a90df1904da912,
    0x2434a84be5b684a5,
    0xd30c04a5f2586e4f,
    0xef8ea76db306cad4,
    0x7f29632535392bc7,
    0x8c012a2071caecd9,
    0x54c5c5132eaae808,
    0x9e65a24bcb41d3f6,
    0xaabdffec3f061805,
    0x01c747ea6424fc04,
    0x56b57bbf5f6afc04,
    0xc66648576f67b1a5,
    0x08dc7e6d724d4e47,
    0xbda9b281a350ae03,
    0x8ef4f4fdbc3d6c85,
    0xd571e3dc9532c905,
    0x7cc7d1c81116eae0,
};

const FEATURES: SolCompatFeatures = .{
    .struct_size = @sizeOf(SolCompatFeatures),
    .hardcoded_features = &HARDCODED_FEATURES,
    .hardcoded_features_len = HARDCODED_FEATURES.len,
    .supported_features = &SUPPORTED_FEATURES,
    .supported_features_len = SUPPORTED_FEATURES.len,
};

export fn sol_compat_get_features_v1() *const SolCompatFeatures {
    return &FEATURES;
}
