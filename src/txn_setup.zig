const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");
const protobuf = @import("protobuf");

const sysvar = sig.runtime.sysvar;
const features = sig.runtime.features;
const bpf_loader = sig.runtime.program.bpf_loader;
const program_loader = sig.runtime.program_loader;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const EpochStakes = sig.core.stake.EpochStakes;
const AccountSharedData = sig.runtime.AccountSharedData;
const ComputeBudget = sig.runtime.ComputeBudget;
const SysvarCache = sig.runtime.SysvarCache;
const FeatureSet = sig.runtime.FeatureSet;
const TransactionContext = sig.runtime.TransactionContext;
const InstructionInfo = sig.runtime.InstructionInfo;
const VmEnvironment = sig.vm.Environment;
const ProgramMap = sig.runtime.program_loader.ProgramMap;
const TransactionContextAccount = sig.runtime.transaction_context.TransactionContextAccount;
const LogCollector = sig.runtime.LogCollector;
const GenesisConfig = sig.core.GenesisConfig;
const AccountsDb = sig.accounts_db.AccountsDB;

const ManagedString = protobuf.ManagedString;

pub fn parsePubkey(address: ManagedString) !Pubkey {
    if (address.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
    return .{ .data = address.getSlice()[0..Pubkey.SIZE].* };
}

pub fn parseHash(hash: ManagedString) !Hash {
    if (hash.getSlice().len != Hash.SIZE) return error.OutOfBounds;
    return .{ .data = hash.getSlice()[0..Hash.SIZE].* };
}

pub fn toggleDirectMapping(allocator: std.mem.Allocator, feature_set: *FeatureSet) !void {
    if (try std.process.hasEnvVar(allocator, "TOGGLE_DIRECT_MAPPING")) {
        if (feature_set.active.contains(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING)) {
            _ = feature_set.active.swapRemove(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING);
        } else {
            try feature_set.active.put(allocator, features.BPF_ACCOUNT_DATA_DIRECT_MAPPING, 0);
        }
    }
}

/// Initialises genesis configuration for transaction fuzzing.
/// NOTE: Agave adds dummy ALUT accounts to prevent them being loaded into the program cache. Since
/// we use a different program caching approach this is not necessary here. (Maybe...)
/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/0adad0c9bee4bfde02bdc39bc27eaf18873fa039/src/txn_fuzzer.rs#L359-L385
pub fn initGenesisConfig(
    allocator: std.mem.Allocator,
    accounts: []const pb.AcctState,
) !GenesisConfig {
    const rent = (try loadSysvar(
        allocator,
        sysvar.Rent,
        accounts,
    )) orelse sysvar.Rent.DEFAULT;

    const epoch_schedule = (try loadSysvar(
        allocator,
        sysvar.EpochSchedule,
        accounts,
    )) orelse sysvar.EpochSchedule.DEFAULT;

    var genesis_config = GenesisConfig.default(allocator);

    genesis_config.creation_time = 0;
    genesis_config.rent = rent;
    genesis_config.epoch_schedule = epoch_schedule;

    return genesis_config;
}

pub fn initAccountsDb(
    allocator: std.mem.Allocator,
    random: std.Random,
) !AccountsDb {
    const snapshot_dir_name = try std.fmt.allocPrint(
        allocator,
        "snapshot-dir-{}",
        .{random.int(u64)},
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

pub fn loadBlockhashes(
    allocator: std.mem.Allocator,
    pb_blockhashes: []const ManagedString,
) ![]const Hash {
    if (pb_blockhashes.len == 0) {
        return try allocator.dupe(Hash, &.{Hash.ZEROES});
    }

    const blockhashes = try allocator.alloc(Hash, pb_blockhashes.len);
    errdefer allocator.free(blockhashes);

    for (blockhashes, pb_blockhashes) |*blockhash, pb_blockhash| {
        blockhash.* = try parseHash(pb_blockhash);
    }

    return blockhashes;
}

pub fn loadSysvar(
    allocator: std.mem.Allocator,
    comptime T: type,
    accounts: []const pb.AcctState,
) !?T {
    for (accounts) |account| {
        if (account.lamports == 0) continue;
        const account_pubkey = try parsePubkey(account.address);
        if (account_pubkey.equals(&T.ID)) {
            return try sig.bincode.readFromSlice(
                allocator,
                T,
                account.data.getSlice(),
                .{},
            );
        }
    }
    return null;
}

pub fn loadFeatureSet(
    allocator: std.mem.Allocator,
    pb_epoch_context: ?pb.EpochContext,
) !FeatureSet {
    const maybe_pb_features = if (pb_epoch_context) |epoch_ctx|
        if (epoch_ctx.features) |pb_features| pb_features else null
    else
        null;

    const pb_features = maybe_pb_features orelse return FeatureSet.EMPTY;

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

    return feature_set;
}

const program = sig.runtime.program;

/// Loads builtin programs into the intial accounts map.
/// The ALUT and Config Programs have been migrated to Core BPF and are hence not included here.
/// The ZK Token Proof and ZK El Gamal Proof programs are not included as they have not been implemented yet.
pub fn loadBuiltins(
    allocator: std.mem.Allocator,
    accounts: std.AutoArrayHashMapUnmanaged(Pubkey, struct { u64, AccountSharedData }),
) !void {
    // System Program
    try accounts.put(program.system.ID, allocator, .{ 0, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "system_program"),
    } });

    // Vote Program
    try accounts.put(program.vote.ID, allocator, .{ 0, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "vote_program"),
    } });

    // Stake Program
    try accounts.put(program.stake.ID, allocator, .{ 0, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "stake_program"),
    } });

    // BPF Loader Program V1
    try accounts.put(bpf_loader.v1.ID, allocator, .{ 0, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "solana_bpf_loader_deprecated_program"),
    } });

    // BPF Loader Program V2
    try accounts.put(bpf_loader.v2.ID, allocator, .{ 0, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "solana_bpf_loader_program"),
    } });

    // BPF Loader Program V3
    try accounts.put(bpf_loader.v3.ID, allocator, .{ 0, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "solana_bpf_loader_upgradeable_program"),
    } });

    // Compute Budget Program
    try accounts.put(program.compute_budget.ID, allocator, .{ 0, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, "compute_budget_program"),
    } });

    // TODO: ZK Token Proof Program
    // TODO: ZK El Gamal Proof Program
}

pub fn loadPrecompiles(
    allocator: std.mem.Allocator,
    accounts: std.AutoArrayHashMapUnmanaged(Pubkey, struct { u64, AccountSharedData }),
) !void {
    // Ed25519 Precompile
    try accounts.put(program.precompiles.ed25519.ID, allocator, .{ 0, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, ""),
    } });

    // Keccak256 Precompile
    try accounts.put(program.precompiles.secp256k1, allocator, .{ 0, .{
        .lamports = 1,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .rent_epoch = 0,
        .data = try allocator.dupe(u8, ""),
    } });
}

const TransactionResult = sig.runtime.transaction_execution.TransactionResult;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;

pub fn createTxnResult(result: TransactionResult(ProcessedTransaction)) pb.TxnResult {
    switch (result) {
        .ok => |transaction| {
            _ = transaction;
            // let is_ok = match txn {
            //     ProcessedTransaction::Executed(executed_tx) => {
            //         executed_tx.execution_details.status.is_ok()
            //     }
            //     ProcessedTransaction::FeesOnly(_) => false,
            // };

            // let loaded_accounts_data_size = match txn {
            //     ProcessedTransaction::Executed(executed_tx) => {
            //         executed_tx.loaded_transaction.loaded_accounts_data_size
            //     }
            //     ProcessedTransaction::FeesOnly(fees_only_tx) => {
            //         fees_only_tx.rollback_accounts.data_size() as u32
            //     }
            // };

            // let (status, instr_err, custom_err, instr_err_idx) =
            //     match txn.status().as_ref().map_err(transaction_error_to_err_nums) {
            //         Ok(_) => (0, 0, 0, 0),
            //         Err((status, instr_err, custom_err, instr_err_idx)) => {
            //             // Set custom err to 0 if the failing instruction is a precompile
            //             let custom_err_ret = sanitized_message
            //                 .instructions()
            //                 .get(instr_err_idx as usize)
            //                 .and_then(|instr| {
            //                     sanitized_message
            //                         .account_keys()
            //                         .get(instr.program_id_index as usize)
            //                         .map(|program_id| {
            //                             if get_precompile(program_id, |_| true).is_some() {
            //                                 0
            //                             } else {
            //                                 custom_err
            //                             }
            //                         })
            //                 })
            //                 .unwrap_or(custom_err);
            //             (status, instr_err, custom_err_ret, instr_err_idx)
            //         }
            //     };
            // let rent = match txn {
            //     ProcessedTransaction::Executed(executed_tx) => executed_tx.loaded_transaction.rent,
            //     ProcessedTransaction::FeesOnly(_) => 0,
            // };
            // let resulting_state: Option<ResultingState> = match txn {
            //     ProcessedTransaction::Executed(executed_tx) => {
            //         Some(executed_tx.loaded_transaction.clone().into())
            //     }
            //     ProcessedTransaction::FeesOnly(tx) => {
            //         let mut accounts = Vec::with_capacity(tx.rollback_accounts.count());
            //         collect_accounts_for_failed_tx(
            //             &mut accounts,
            //             &mut None,
            //             sanitized_message,
            //             None,
            //             &tx.rollback_accounts,
            //         );
            //         Some(ResultingState {
            //             acct_states: accounts
            //                 .iter()
            //                 .map(|&(pubkey, acct)| (*pubkey, acct.clone()).into())
            //                 .collect(),
            //             rent_debits: vec![],
            //             transaction_rent: 0,
            //         })
            //     }
            // };
            // let executed_units = match txn {
            //     ProcessedTransaction::Executed(executed_tx) => {
            //         executed_tx.execution_details.executed_units
            //     }
            //     ProcessedTransaction::FeesOnly(_) => 0,
            // };
            // let return_data = match txn {
            //     ProcessedTransaction::Executed(executed_tx) => executed_tx
            //         .execution_details
            //         .return_data
            //         .as_ref()
            //         .map(|info| info.clone().data)
            //         .unwrap_or_default(),
            //     ProcessedTransaction::FeesOnly(_) => vec![],
            // };
            // (
            //     is_ok,
            //     false,
            //     status,
            //     instr_err,
            //     instr_err_idx,
            //     custom_err,
            //     executed_units,
            //     return_data,
            //     Some(txn.fee_details()),
            //     rent,
            //     loaded_accounts_data_size,
            //     resulting_state,
            // )
        },
        .err => |err| {
            _ = err;
            // let (status, instr_err, custom_err, instr_err_idx) =
            //     transaction_error_to_err_nums(transaction_error);
            // (
            //     false,
            //     true,
            //     status,
            //     instr_err,
            //     instr_err_idx,
            //     custom_err,
            //     0,
            //     vec![],
            //     None,
            //     0,
            //     0,
            //     None,
            // )
        },
    }
}

// pub fn updateSysvarAccount(comptime T: type, data: T, accounts_db: AccountsDb) !void {

// }
