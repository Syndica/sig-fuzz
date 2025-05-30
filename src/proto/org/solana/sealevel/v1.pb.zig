// Code generated by protoc-gen-zig
///! package org.solana.sealevel.v1
const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const protobuf = @import("protobuf");
const ManagedString = protobuf.ManagedString;
const fd = protobuf.fd;
const ManagedStruct = protobuf.ManagedStruct;

pub const FeatureSet = struct {
    features: ArrayList(u64),

    pub const _desc_table = .{
        .features = fd(1, .{ .PackedList = .{ .FixedInt = .I64 } }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const SeedAddress = struct {
    base: ManagedString = .Empty,
    seed: ManagedString = .Empty,
    owner: ManagedString = .Empty,

    pub const _desc_table = .{
        .base = fd(1, .Bytes),
        .seed = fd(2, .Bytes),
        .owner = fd(3, .Bytes),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const AcctState = struct {
    address: ManagedString = .Empty,
    lamports: u64 = 0,
    data: ManagedString = .Empty,
    executable: bool = false,
    rent_epoch: u64 = 0,
    owner: ManagedString = .Empty,
    seed_addr: ?SeedAddress = null,

    pub const _desc_table = .{
        .address = fd(1, .Bytes),
        .lamports = fd(2, .{ .Varint = .Simple }),
        .data = fd(3, .Bytes),
        .executable = fd(4, .{ .Varint = .Simple }),
        .rent_epoch = fd(5, .{ .Varint = .Simple }),
        .owner = fd(6, .Bytes),
        .seed_addr = fd(7, .{ .SubMessage = {} }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const EpochContext = struct {
    features: ?FeatureSet = null,

    pub const _desc_table = .{
        .features = fd(1, .{ .SubMessage = {} }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const SlotContext = struct {
    slot: u64 = 0,

    pub const _desc_table = .{
        .slot = fd(1, .{ .FixedInt = .I64 }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const FixtureMetadata = struct {
    fn_entrypoint: ManagedString = .Empty,

    pub const _desc_table = .{
        .fn_entrypoint = fd(1, .String),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const ELFBinary = struct {
    data: ManagedString = .Empty,

    pub const _desc_table = .{
        .data = fd(1, .Bytes),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const ELFLoaderCtx = struct {
    elf: ?ELFBinary = null,
    features: ?FeatureSet = null,
    elf_sz: u64 = 0,
    deploy_checks: bool = false,

    pub const _desc_table = .{
        .elf = fd(1, .{ .SubMessage = {} }),
        .features = fd(2, .{ .SubMessage = {} }),
        .elf_sz = fd(3, .{ .Varint = .Simple }),
        .deploy_checks = fd(4, .{ .Varint = .Simple }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const ELFLoaderEffects = struct {
    rodata: ManagedString = .Empty,
    rodata_sz: u64 = 0,
    text_cnt: u64 = 0,
    text_off: u64 = 0,
    entry_pc: u64 = 0,
    calldests: ArrayList(u64),

    pub const _desc_table = .{
        .rodata = fd(1, .Bytes),
        .rodata_sz = fd(2, .{ .Varint = .Simple }),
        .text_cnt = fd(4, .{ .Varint = .Simple }),
        .text_off = fd(5, .{ .Varint = .Simple }),
        .entry_pc = fd(6, .{ .Varint = .Simple }),
        .calldests = fd(7, .{ .PackedList = .{ .Varint = .Simple } }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const ELFLoaderFixture = struct {
    metadata: ?FixtureMetadata = null,
    input: ?ELFLoaderCtx = null,
    output: ?ELFLoaderEffects = null,

    pub const _desc_table = .{
        .metadata = fd(1, .{ .SubMessage = {} }),
        .input = fd(2, .{ .SubMessage = {} }),
        .output = fd(3, .{ .SubMessage = {} }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const InstrAcct = struct {
    index: u32 = 0,
    is_writable: bool = false,
    is_signer: bool = false,

    pub const _desc_table = .{
        .index = fd(1, .{ .Varint = .Simple }),
        .is_writable = fd(2, .{ .Varint = .Simple }),
        .is_signer = fd(3, .{ .Varint = .Simple }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const InstrContext = struct {
    program_id: ManagedString = .Empty,
    accounts: ArrayList(AcctState),
    instr_accounts: ArrayList(InstrAcct),
    data: ManagedString = .Empty,
    cu_avail: u64 = 0,
    slot_context: ?SlotContext = null,
    epoch_context: ?EpochContext = null,

    pub const _desc_table = .{
        .program_id = fd(1, .Bytes),
        .accounts = fd(3, .{ .List = .{ .SubMessage = {} } }),
        .instr_accounts = fd(4, .{ .List = .{ .SubMessage = {} } }),
        .data = fd(5, .Bytes),
        .cu_avail = fd(6, .{ .Varint = .Simple }),
        .slot_context = fd(8, .{ .SubMessage = {} }),
        .epoch_context = fd(9, .{ .SubMessage = {} }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const InstrEffects = struct {
    result: i32 = 0,
    custom_err: u32 = 0,
    modified_accounts: ArrayList(AcctState),
    cu_avail: u64 = 0,
    return_data: ManagedString = .Empty,

    pub const _desc_table = .{
        .result = fd(1, .{ .Varint = .Simple }),
        .custom_err = fd(2, .{ .Varint = .Simple }),
        .modified_accounts = fd(3, .{ .List = .{ .SubMessage = {} } }),
        .cu_avail = fd(4, .{ .Varint = .Simple }),
        .return_data = fd(5, .Bytes),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const InstrFixture = struct {
    metadata: ?FixtureMetadata = null,
    input: ?InstrContext = null,
    output: ?InstrEffects = null,

    pub const _desc_table = .{
        .metadata = fd(1, .{ .SubMessage = {} }),
        .input = fd(2, .{ .SubMessage = {} }),
        .output = fd(3, .{ .SubMessage = {} }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const ErrKind = enum(i32) {
    UNSPECIFIED = 0,
    EBPF = 1,
    SYSCALL = 2,
    INSTRUCTION = 3,
    _,
};

pub const InputDataRegion = struct {
    offset: u64 = 0,
    content: ManagedString = .Empty,
    is_writable: bool = false,

    pub const _desc_table = .{
        .offset = fd(1, .{ .Varint = .Simple }),
        .content = fd(2, .Bytes),
        .is_writable = fd(3, .{ .Varint = .Simple }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const VmContext = struct {
    heap_max: u64 = 0,
    rodata: ManagedString = .Empty,
    rodata_text_section_offset: u64 = 0,
    rodata_text_section_length: u64 = 0,
    input_data_regions: ArrayList(InputDataRegion),
    r0: u64 = 0,
    r1: u64 = 0,
    r2: u64 = 0,
    r3: u64 = 0,
    r4: u64 = 0,
    r5: u64 = 0,
    r6: u64 = 0,
    r7: u64 = 0,
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r11: u64 = 0,
    check_align: bool = false,
    check_size: bool = false,
    entry_pc: u64 = 0,
    call_whitelist: ManagedString = .Empty,
    tracing_enabled: bool = false,
    return_data: ?ReturnData = null,
    sbpf_version: u32 = 0,

    pub const _desc_table = .{
        .heap_max = fd(1, .{ .Varint = .Simple }),
        .rodata = fd(2, .Bytes),
        .rodata_text_section_offset = fd(3, .{ .Varint = .Simple }),
        .rodata_text_section_length = fd(4, .{ .Varint = .Simple }),
        .input_data_regions = fd(5, .{ .List = .{ .SubMessage = {} } }),
        .r0 = fd(6, .{ .Varint = .Simple }),
        .r1 = fd(7, .{ .Varint = .Simple }),
        .r2 = fd(8, .{ .Varint = .Simple }),
        .r3 = fd(9, .{ .Varint = .Simple }),
        .r4 = fd(10, .{ .Varint = .Simple }),
        .r5 = fd(11, .{ .Varint = .Simple }),
        .r6 = fd(12, .{ .Varint = .Simple }),
        .r7 = fd(13, .{ .Varint = .Simple }),
        .r8 = fd(14, .{ .Varint = .Simple }),
        .r9 = fd(15, .{ .Varint = .Simple }),
        .r10 = fd(16, .{ .Varint = .Simple }),
        .r11 = fd(17, .{ .Varint = .Simple }),
        .check_align = fd(18, .{ .Varint = .Simple }),
        .check_size = fd(19, .{ .Varint = .Simple }),
        .entry_pc = fd(20, .{ .Varint = .Simple }),
        .call_whitelist = fd(21, .Bytes),
        .tracing_enabled = fd(22, .{ .Varint = .Simple }),
        .return_data = fd(23, .{ .SubMessage = {} }),
        .sbpf_version = fd(24, .{ .Varint = .Simple }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const SyscallInvocation = struct {
    function_name: ManagedString = .Empty,
    heap_prefix: ManagedString = .Empty,
    stack_prefix: ManagedString = .Empty,

    pub const _desc_table = .{
        .function_name = fd(1, .Bytes),
        .heap_prefix = fd(2, .Bytes),
        .stack_prefix = fd(3, .Bytes),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const SyscallContext = struct {
    vm_ctx: ?VmContext = null,
    instr_ctx: ?InstrContext = null,
    syscall_invocation: ?SyscallInvocation = null,
    exec_effects: ?InstrEffects = null,

    pub const _desc_table = .{
        .vm_ctx = fd(1, .{ .SubMessage = {} }),
        .instr_ctx = fd(2, .{ .SubMessage = {} }),
        .syscall_invocation = fd(3, .{ .SubMessage = {} }),
        .exec_effects = fd(4, .{ .SubMessage = {} }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const SyscallEffects = struct {
    @"error": i64 = 0,
    error_kind: ErrKind = @enumFromInt(0),
    r0: u64 = 0,
    cu_avail: u64 = 0,
    heap: ManagedString = .Empty,
    stack: ManagedString = .Empty,
    inputdata: ManagedString = .Empty,
    input_data_regions: ArrayList(InputDataRegion),
    frame_count: u64 = 0,
    log: ManagedString = .Empty,
    rodata: ManagedString = .Empty,
    pc: u64 = 0,
    r1: u64 = 0,
    r2: u64 = 0,
    r3: u64 = 0,
    r4: u64 = 0,
    r5: u64 = 0,
    r6: u64 = 0,
    r7: u64 = 0,
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,

    pub const _desc_table = .{
        .@"error" = fd(1, .{ .Varint = .Simple }),
        .error_kind = fd(12, .{ .Varint = .Simple }),
        .r0 = fd(2, .{ .Varint = .Simple }),
        .cu_avail = fd(3, .{ .Varint = .Simple }),
        .heap = fd(4, .Bytes),
        .stack = fd(5, .Bytes),
        .inputdata = fd(6, .Bytes),
        .input_data_regions = fd(11, .{ .List = .{ .SubMessage = {} } }),
        .frame_count = fd(7, .{ .Varint = .Simple }),
        .log = fd(8, .Bytes),
        .rodata = fd(9, .Bytes),
        .pc = fd(10, .{ .Varint = .Simple }),
        .r1 = fd(107, .{ .Varint = .Simple }),
        .r2 = fd(108, .{ .Varint = .Simple }),
        .r3 = fd(109, .{ .Varint = .Simple }),
        .r4 = fd(110, .{ .Varint = .Simple }),
        .r5 = fd(111, .{ .Varint = .Simple }),
        .r6 = fd(112, .{ .Varint = .Simple }),
        .r7 = fd(113, .{ .Varint = .Simple }),
        .r8 = fd(114, .{ .Varint = .Simple }),
        .r9 = fd(115, .{ .Varint = .Simple }),
        .r10 = fd(116, .{ .Varint = .Simple }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const SyscallFixture = struct {
    metadata: ?FixtureMetadata = null,
    input: ?SyscallContext = null,
    output: ?SyscallEffects = null,

    pub const _desc_table = .{
        .metadata = fd(1, .{ .SubMessage = {} }),
        .input = fd(2, .{ .SubMessage = {} }),
        .output = fd(3, .{ .SubMessage = {} }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const FullVmContext = struct {
    vm_ctx: ?VmContext = null,
    features: ?FeatureSet = null,

    pub const _desc_table = .{
        .vm_ctx = fd(1, .{ .SubMessage = {} }),
        .features = fd(3, .{ .SubMessage = {} }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const ValidateVmEffects = struct {
    result: i32 = 0,
    success: bool = false,

    pub const _desc_table = .{
        .result = fd(1, .{ .Varint = .Simple }),
        .success = fd(2, .{ .Varint = .Simple }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const ValidateVmFixture = struct {
    metadata: ?FixtureMetadata = null,
    input: ?FullVmContext = null,
    output: ?ValidateVmEffects = null,

    pub const _desc_table = .{
        .metadata = fd(1, .{ .SubMessage = {} }),
        .input = fd(2, .{ .SubMessage = {} }),
        .output = fd(3, .{ .SubMessage = {} }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const ReturnData = struct {
    program_id: ManagedString = .Empty,
    data: ManagedString = .Empty,

    pub const _desc_table = .{
        .program_id = fd(1, .Bytes),
        .data = fd(2, .Bytes),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const ShredBinary = struct {
    data: ManagedString = .Empty,

    pub const _desc_table = .{
        .data = fd(1, .Bytes),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const DataHeader = struct {
    parent_off: u32 = 0,
    flags: u32 = 0,
    size: u32 = 0,

    pub const _desc_table = .{
        .parent_off = fd(1, .{ .Varint = .Simple }),
        .flags = fd(2, .{ .Varint = .Simple }),
        .size = fd(3, .{ .Varint = .Simple }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const CodeHeader = struct {
    data_cnt: u32 = 0,
    code_cnt: u32 = 0,
    idx: u32 = 0,

    pub const _desc_table = .{
        .data_cnt = fd(1, .{ .Varint = .Simple }),
        .code_cnt = fd(2, .{ .Varint = .Simple }),
        .idx = fd(3, .{ .Varint = .Simple }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const ParsedShred = struct {
    signature: ManagedString = .Empty,
    variant: u32 = 0,
    slot: u64 = 0,
    idx: u32 = 0,
    version: u32 = 0,
    fec_set_idx: u32 = 0,
    shred_type: ?shred_type_union,

    pub const _shred_type_case = enum {
        data,
        code,
    };
    pub const shred_type_union = union(_shred_type_case) {
        data: DataHeader,
        code: CodeHeader,
        pub const _union_desc = .{
            .data = fd(7, .{ .SubMessage = {} }),
            .code = fd(8, .{ .SubMessage = {} }),
        };
    };

    pub const _desc_table = .{
        .signature = fd(1, .String),
        .variant = fd(2, .{ .Varint = .Simple }),
        .slot = fd(3, .{ .Varint = .Simple }),
        .idx = fd(4, .{ .Varint = .Simple }),
        .version = fd(5, .{ .Varint = .Simple }),
        .fec_set_idx = fd(6, .{ .Varint = .Simple }),
        .shred_type = fd(null, .{ .OneOf = shred_type_union }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};

pub const AcceptsShred = struct {
    valid: bool = false,

    pub const _desc_table = .{
        .valid = fd(1, .{ .Varint = .Simple }),
    };

    pub usingnamespace protobuf.MessageMixins(@This());
};
