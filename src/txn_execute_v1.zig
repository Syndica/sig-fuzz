const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");

const EMIT_LOGS = false;

/// [fd] https://github.com/firedancer-io/firedancer/blob/61e3d2e21419fc71002aa1c037ab637cea85416d/src/flamenco/runtime/tests/harness/fd_exec_sol_compat.c#L583
/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/7d039a85e55227fdd7ae5c9d0e1c36c7cf5b01f5/src/txn_fuzzer.rs#L46
export fn sol_compat_txn_execute_v1(
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
    var pb_txn_ctx = pb.TxnContext.decode(
        in_slice,
        decode_arena.allocator(),
    ) catch |err| {
        std.debug.print("pb.TxnContext.decode: {s}\n", .{@errorName(err)});
        return 0;
    };
    defer pb_txn_ctx.deinit();

    const result = executeTxnContext(allocator, pb_txn_ctx, EMIT_LOGS) catch |err| {
        std.debug.print("executeTxnContext: {s}\n", .{@errorName(err)});
        return 0;
    };

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

const bincode = sig.bincode;
const features = sig.runtime.features;
const program = sig.runtime.program;
const sysvar = sig.runtime.sysvar;

const AccountsDb = sig.accounts_db.AccountsDB;

const Ancestors = sig.core.Ancestors;
const BlockhashQueue = sig.core.BlockhashQueue;
const EpochStakes = sig.core.EpochStakes;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.RentCollector;
const Signature = sig.core.Signature;
const StatusCache = sig.core.StatusCache;
const Transaction = sig.core.Transaction;
const TransactionVersion = sig.core.transaction.Version;
const TransactionMessage = sig.core.transaction.Message;
const TransactionInstruction = sig.core.transaction.Instruction;
const TransactionAddressLookup = sig.core.transaction.AddressLookup;

const Rent = sig.runtime.sysvar.Rent;
const EpochSchedule = sig.runtime.sysvar.EpochSchedule;
const SlotHashes = sig.runtime.sysvar.SlotHashes;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const LastRestartSlot = sig.runtime.sysvar.LastRestartSlot;
const Clock = sig.runtime.sysvar.Clock;

const AccountSharedData = sig.runtime.AccountSharedData;
const FeatureSet = sig.runtime.features.FeatureSet;
const SysvarCache = sig.runtime.SysvarCache;

fn executeTxnContext(allocator: std.mem.Allocator, pb_txn_ctx: pb.TxnContext, emit_logs: bool) !pb.TxnResult {
    // Load info from the protobuf transaction context
    const slot = loadSlot(&pb_txn_ctx);
    const feature_set = try loadFeatureSet(allocator, &pb_txn_ctx);
    const blockhashes = try loadBlockhashes(allocator, &pb_txn_ctx);
    const transaction = try loadTransaction(allocator, &pb_txn_ctx);

    // Load accounts from the protobuf transaction context
    // Sysvar defaults may be added to this account map before adding all accounts to accounts db for
    // the specified slot.
    var accounts = try loadAccounts(allocator, &pb_txn_ctx);
    defer {
        for (accounts.values()) |acc| allocator.free(acc.data);
        accounts.deinit(allocator);
    }

    // Builtin accounts must also be loaded into accounts db, these accounts will be loaded at
    // genesis i.e. slot 0.
    // TODO: We will need to add feature gating here for new builtin programs and core bpf migration.
    const builtin_accounts = try loadBuiltins(allocator);
    defer {
        for (builtin_accounts.values()) |acc| allocator.free(acc.data);
        var ba = builtin_accounts;
        ba.deinit(allocator);
    }

    const epoch_schedule = loadSysvar(
        allocator,
        EpochSchedule,
        &accounts,
    ) orelse EpochSchedule.DEFAULT;

    const rent: Rent = loadSysvar(
        allocator,
        Rent,
        &accounts,
    ) orelse Rent.DEFAULT;

    // Provide default slot hashes of size 1 if not provided
    _ = loadSysvar(
        allocator,
        SlotHashes,
        &accounts,
    ) orelse blk: {
        const slot_hashes = SlotHashes{
            .entries = try allocator.dupe(struct { u64, Hash }, &.{.{ slot, Hash.ZEROES }}),
        };

        const slot_hashes_data = try allocator.alloc(u8, SlotHashes.SIZE_OF);
        errdefer allocator.free(slot_hashes_data);

        try bincode.writeToSlice(slot_hashes_data, slot_hashes, .{});

        accounts.put(allocator, SlotHashes.ID, .{
            .lamports = @max(1, rent.minimumBalance(slot_hashes_data.len)),
            .data = slot_hashes_data,
            .owner = sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        });

        break :blk slot_hashes;
    };

    // Provide default stake history if not provided
    _ = loadSysvar(
        allocator,
        StakeHistory,
        &accounts,
    ) orelse blk: {
        const stake_history = StakeHistory{
            .entries = try allocator.dupe(
                struct { u64, StakeHistory.Entry },
                &.{.{ 0, .{ .effective = 0, .activating = 0, .deactivating = 0 } }},
            ),
        };

        const stake_history_data = try allocator.alloc(u8, StakeHistory.SIZE_OF);
        errdefer allocator.free(stake_history_data);

        try bincode.writeToSlice(stake_history_data, stake_history, .{});

        accounts.put(allocator, StakeHistory.ID, .{
            .lamports = @max(1, rent.minimumBalance(stake_history_data.len)),
            .data = stake_history_data,
            .owner = sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        });

        // TODO: stake_history_update

        break :blk stake_history;
    };

    // Provide default last restart slot sysvar if not provided
    _ = loadSysvar(
        allocator,
        LastRestartSlot,
        &accounts,
    ) orelse blk: {
        const last_restart_slot = LastRestartSlot{
            .last_restart_slot = 0,
        };

        const last_restart_slot_data = try allocator.alloc(u8, LastRestartSlot.SIZE_OF);
        errdefer allocator.free(last_restart_slot_data);

        try bincode.writeToSlice(last_restart_slot_data, last_restart_slot, .{});

        accounts.put(allocator, LastRestartSlot.ID, .{
            .lamports = @max(1, rent.minimumBalance(last_restart_slot_data.len)),
            .data = last_restart_slot_data,
            .owner = sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        });

        break :blk last_restart_slot;
    };

    // Provide a default clock if not present
    _ = loadSysvar(
        allocator,
        Clock,
        &accounts,
    ) orelse blk: {
        const clock = Clock{
            .epoch = 0,
            .epoch_start_timestamp = 0,
            .unix_timestamp = 0,
            .slot = slot,
            .leader_schedule_epoch = 1,
        };

        const clock_data = try allocator.alloc(u8, Clock.SIZE_OF);
        errdefer allocator.free(clock_data);

        try bincode.writeToSlice(clock_data, clock, .{});

        accounts.put(allocator, Clock.ID, .{
            .lamports = @max(1, rent.minimumBalance(clock_data.len)),
            .data = clock_data,
            .owner = sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        });

        // TODO: stake_history_update

        break :blk clock;
    };

    // Epoch schedule and rent get set from the epoch bank

    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);

    var status_cache = StatusCache.default();
    defer status_cache.deinit(allocator);

    var sysvar_cache = SysvarCache{};
    defer sysvar_cache.deinit(allocator);

    const rent_collector = RentCollector{
        .epoch = 0,
        .epoch_schedule = .DEFAULT,
        .slots_per_year = 0,
        .rent = .{
            .lamports_per_byte_year = 0,
            .exemption_threshold = 0,
            .burn_percent = 0,
        },
    };

    var blockhash_queue = BlockhashQueue.init(300);
    defer blockhash_queue.deinit(allocator);

    var epoch_stakes = EpochStakes.EMPTY;
    defer epoch_stakes.deinit(allocator);

    // _ = slot;
    // _ = feature_set;
    // _ = blockhashes;
    // _ = accounts;
    // _ = transaction;
    _ = rent_collector;
    _ = emit_logs;

    return .{};
}

fn loadHash(bytes: []const u8) !Hash {
    if (bytes.len != Hash.SIZE) return error.OutOfBounds;
    return .{ .data = bytes[0..Hash.SIZE].* };
}

fn loadPubkey(bytes: []const u8) !Pubkey {
    if (bytes.len != Pubkey.SIZE) return error.OutOfBounds;
    return .{ .data = bytes[0..Pubkey.SIZE].* };
}

fn loadSlot(pb_txn_ctx: *const pb.TxnContext) u64 {
    return if (pb_txn_ctx.slot_ctx) |ctx| ctx.slot else 10;
}

fn loadFeatureSet(allocator: std.mem.Allocator, pb_txn_ctx: *const pb.TxnContext) !FeatureSet {
    var feature_set = blk: {
        const maybe_pb_features = if (pb_txn_ctx.epoch_ctx) |epoch_ctx|
            if (epoch_ctx.features) |pb_features| pb_features else null
        else
            null;

        const pb_features = maybe_pb_features orelse break :blk FeatureSet.EMPTY;

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

        break :blk feature_set;
    };

    if (try std.process.hasEnvVar(allocator, "TOGGLE_DIRECT_MAPPING")) {
        if (feature_set.active.contains(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING)) {
            _ = feature_set.active.swapRemove(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING);
        } else {
            try feature_set.active.put(allocator, features.BPF_ACCOUNT_DATA_DIRECT_MAPPING, 0);
        }
    }

    return feature_set;
}

fn loadBlockhashes(
    allocator: std.mem.Allocator,
    pb_txn_ctx: *const pb.TxnContext,
) ![]Hash {
    const pb_blockhashes = pb_txn_ctx.blockhash_queue.items;
    if (pb_blockhashes.len == 0)
        return try allocator.dupe(Hash, &.{Hash.ZEROES});

    const blockhashes = try allocator.alloc(Hash, pb_blockhashes.len);
    errdefer allocator.free(blockhashes);

    for (blockhashes, pb_blockhashes) |*blockhash, pb_blockhash|
        blockhash.* = try loadHash(pb_blockhash.getSlice());

    return blockhashes;
}

fn loadAccounts(
    allocator: std.mem.Allocator,
    pb_txn_ctx: *const pb.TxnContext,
) !std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData) {
    const pb_accounts = pb_txn_ctx.account_shared_data.items;

    var accounts = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData){};
    errdefer {
        for (accounts.values()) |acc| allocator.free(acc.data);
        accounts.deinit(allocator);
    }

    for (pb_accounts) |pb_account| {
        if (pb_account.lamports == 0) continue;
        try accounts.put(allocator, try loadPubkey(pb_account.address.getSlice()), .{
            .lamports = pb_account.lamports,
            .data = try allocator.dupe(u8, pb_account.data.getSlice()),
            .owner = try loadPubkey(pb_account.owner.getSlice()),
            .executable = pb_account.executable,
            .rent_epoch = pb_account.rent_epoch,
        });
    }

    return accounts;
}

fn loadTransaction(
    allocator: std.mem.Allocator,
    pb_txn_ctx: *const pb.TxnContext,
) !Transaction {
    const pb_txn = pb_txn_ctx.tx orelse return error.NoTransaction;

    const signatures = try allocator.alloc(
        Signature,
        @max(pb_txn.signatures.items.len, 1),
    );

    for (pb_txn.signatures.items, 0..) |pb_signature, i|
        signatures[i] = .{ .data = pb_signature.getSlice()[0..Signature.SIZE].* };

    if (pb_txn.signatures.items.len == 0)
        signatures[0] = Signature.ZEROES;

    const version, const message = try loadTransactionMesssage(
        allocator,
        pb_txn.message.?,
    );

    return .{
        .signatures = signatures,
        .version = version,
        .msg = message,
    };
}

fn loadTransactionMesssage(
    allocator: std.mem.Allocator,
    message: pb.TransactionMessage,
) !struct { TransactionVersion, TransactionMessage } {
    const account_keys = try allocator.alloc(Pubkey, message.account_keys.items.len);
    for (account_keys, message.account_keys.items) |*account_key, pb_account_key|
        account_key.* = .{ .data = pb_account_key.getSlice()[0..Pubkey.SIZE].* };

    const recent_blockhash = Hash{ .data = message.recent_blockhash.getSlice()[0..Hash.SIZE].* };

    const instructions = try allocator.alloc(
        TransactionInstruction,
        message.instructions.items.len,
    );
    for (instructions, message.instructions.items) |*instruction, pb_instruction| {
        const account_indexes = try allocator.alloc(u8, pb_instruction.accounts.items.len);
        for (account_indexes, pb_instruction.accounts.items) |*account_index, pb_account_index|
            account_index.* = @truncate(pb_account_index);
        instruction.* = .{
            .program_index = @truncate(pb_instruction.program_id_index),
            .account_indexes = account_indexes,
            .data = try allocator.dupe(u8, pb_instruction.data.getSlice()),
        };
    }

    const address_lookups = try allocator.alloc(
        TransactionAddressLookup,
        message.address_table_lookups.items.len,
    );
    for (address_lookups, message.address_table_lookups.items) |*lookup, pb_lookup| {
        const writable_indexes = try allocator.alloc(u8, pb_lookup.writable_indexes.items.len);
        for (writable_indexes, pb_lookup.writable_indexes.items) |*writable_index, pb_writable_index|
            writable_index.* = @truncate(pb_writable_index);

        const readonly_indexes = try allocator.alloc(u8, pb_lookup.readonly_indexes.items.len);
        for (readonly_indexes, pb_lookup.readonly_indexes.items) |*readonly_index, pb_readonly_index|
            readonly_index.* = @truncate(pb_readonly_index);

        lookup.* = TransactionAddressLookup{
            .table_address = Pubkey{ .data = pb_lookup.account_key.getSlice()[0..Pubkey.SIZE].* },
            .writable_indexes = writable_indexes,
            .readonly_indexes = readonly_indexes,
        };
    }

    const header = message.header orelse pb.MessageHeader{
        .num_required_signatures = 1,
        .num_readonly_signed_accounts = 0,
        .num_readonly_unsigned_accounts = 0,
    };

    return .{
        if (message.is_legacy)
            .legacy
        else
            .v0,
        .{
            .signature_count = @truncate(@max(1, header.num_required_signatures)),
            .readonly_signed_count = @truncate(header.num_readonly_signed_accounts),
            .readonly_unsigned_count = @truncate(header.num_readonly_unsigned_accounts),
            .account_keys = account_keys,
            .recent_blockhash = recent_blockhash,
            .instructions = instructions,
            .address_lookups = address_lookups,
        },
    };
}

/// Loads builtin programs into the intial accounts map.
/// The ALUT and Config Programs have been migrated to Core BPF and are hence not included here.
/// The ZK Token Proof and ZK El Gamal Proof programs are not included as they have not been implemented yet.
/// TODO: Add feature activations and core bpf handling
pub fn loadBuiltins(
    allocator: std.mem.Allocator,
) !std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData) {
    var accounts = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData){};
    errdefer {
        for (accounts.values()) |acc| allocator.free(acc.data);
        accounts.deinit(allocator);
    }

    // System Program
    try accounts.put(allocator, program.system.ID, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "system_program"),
    });

    // Vote Program
    try accounts.put(allocator, program.vote.ID, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "vote_program"),
    });

    // Stake Program
    try accounts.put(allocator, program.stake.ID, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "stake_program"),
    });

    // BPF Loader Program V1
    try accounts.put(allocator, program.bpf_loader.v1.ID, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "solana_bpf_loader_deprecated_program"),
    });

    // BPF Loader Program V2
    try accounts.put(allocator, program.bpf_loader.v2.ID, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "solana_bpf_loader_program"),
    });

    // BPF Loader Program V3
    try accounts.put(allocator, program.bpf_loader.v3.ID, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "solana_bpf_loader_upgradeable_program"),
    });

    // Compute Budget Program
    try accounts.put(allocator, program.compute_budget.ID, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "compute_budget_program"),
    });

    // TODO: ZK Token Proof Program
    // TODO: ZK El Gamal Proof Program

    // Ed25519 Precompile
    try accounts.put(allocator, program.precompiles.ed25519.ID, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, ""),
    });

    // Secp256k1 Precompile
    try accounts.put(allocator, program.precompiles.secp256k1.ID, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, ""),
    });

    // TODO: Secp256r1 Precompile

    return accounts;
}

pub fn loadSysvar(
    allocator: std.mem.Allocator,
    comptime T: type,
    accounts: *const std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
) ?T {
    const account = accounts.getPtr(T.ID) orelse return null;
    return sig.bincode.readFromSlice(
        allocator,
        T,
        account.data,
        .{},
    ) catch null;
}

pub fn initAccountsDb(
    allocator: std.mem.Allocator,
    pb_txn_ctx: *const pb.TxnContext,
) !AccountsDb {
    var hasher = std.crypto.hash.Blake3.init(.{});
    const bytes: []const u8 = @as([*]const u8, @ptrCast(&pb_txn_ctx))[0..@sizeOf(pb.TxnContext)];
    hasher.update(bytes);
    var seed = Hash.ZEROES;
    hasher.final(&seed.data);
    var prng = std.Random.DefaultPrng.init(std.mem.bytesAsValue(u64, seed.data[0..8]).*);

    const snapshot_dir_name = try std.fmt.allocPrint(
        allocator,
        "snapshot-dir-{}",
        .{prng.random().int(u64)},
    );
    defer allocator.free(snapshot_dir_name);
    try std.fs.cwd().makeDir(snapshot_dir_name);
    defer std.fs.cwd().deleteTree(snapshot_dir_name) catch {};
    const snapshot_dir = try std.fs.cwd().openDir(
        snapshot_dir_name,
        .{ .iterate = true },
    );

    return try sig.accounts_db.AccountsDB.init(.{
        .allocator = allocator,
        .logger = .noop,
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 1,
        .buffer_pool_frames = 1024,
    });
}
