// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashSet,
    convert::TryFrom,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use anyhow::{format_err, Result};
use diem_client::{
    views::AccountStateWithProofView, AccountAddress, BlockingClient, MethodRequest,
    MethodResponse, SignedTransaction,
};
use diem_logger::*;
use diem_read_write_set::ReadWriteSetAnalysis;
use diem_state_view::StateView;
use diem_transaction_replay::DiemDebugger;
use diem_types::{
    access_path::{self, AccessPath},
    account_state::AccountState,
    account_state_blob::AccountStateBlob,
    transaction::{Transaction, TransactionOutput, TransactionPayload, Version},
};
use diem_validator_interface::{
    DebuggerStateView, DiemValidatorInterface, JsonRpcDebuggerInterface,
};
use diem_vm::{data_cache::RemoteStorage, VMExecutor};
use move_cli::sandbox::utils::{
    mode::{Mode, ModeType},
    on_disk_state_view::OnDiskStateView,
};
use move_core_types::{language_storage::ResourceKey, resolver::MoveResolver};

use structopt::StructOpt;

const DEFAULT_NODE_URL: &str = "http://localhost:8080";

pub struct OnDiskStateViewReader {
    view: OnDiskStateView,
}

struct AccountAddressWithState {
    address: AccountAddress,
    state: AccountState,
}

#[derive(Debug)]
pub struct PrefetchTransactionReplayerConfig {
    build_dir: PathBuf,
    storage_dir: PathBuf,
    rpc_url: String,
    mode_type: ModeType,
}

#[derive(Debug, StructOpt)]
#[structopt(
    about = "Replay transactions using state prefetching",
    rename_all = "kebab-case"
)]
pub struct PrefetchedReplayCLI {
    #[structopt(long, default_value = DEFAULT_NODE_URL)]
    rpc_url: String,

    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    /// Replay transactions starting from version `start` to `start + limit`.
    #[structopt(name = "replay-transactions")]
    ReplayTransactions { start: Version, limit: u64 },

    /// Replay `account` transactions starting from version `start` to `start + limit`.
    #[structopt(name = "replay-account-transactions")]
    ReplayAccountTransactions {
        account: AccountAddress,
        start: Version,
        limit: u64,
    },

    /// Execute serialized transactions from `txs_path`
    #[structopt(name = "execute-serialized-transactions")]
    ExecuteSerializedTransactions { txs_path: PathBuf },
}

pub struct PrefetchTransactionReplayer {
    config: PrefetchTransactionReplayerConfig,
    validator: Box<dyn DiemValidatorInterface>,
    debugger: DiemDebugger,
    rpc_client: BlockingClient,
}

impl StateView for OnDiskStateViewReader {
    fn get(&self, ap: &AccessPath) -> Result<Option<Vec<u8>>> {
        match ap.get_path() {
            access_path::Path::Code(mid) => self.view.get_module_bytes(&mid),
            access_path::Path::Resource(tag) => self.view.get_resource_bytes(ap.address, tag),
        }
    }

    fn is_genesis(&self) -> bool {
        false
    }
}

fn ensure_dir_does_not_exist(dir: &Path) -> Result<()> {
    if dir.exists() {
        Err(format_err!("{:?} must be empty as it will be created", dir))
    } else {
        Ok(())
    }
}

impl PrefetchTransactionReplayer {
    pub fn from_config(config: PrefetchTransactionReplayerConfig) -> Result<Self> {
        ensure_dir_does_not_exist(&config.build_dir)?;
        ensure_dir_does_not_exist(&config.storage_dir)?;

        let debugger = DiemDebugger::json_rpc_with_config(
            &config.rpc_url,
            config.build_dir.clone(),
            config.storage_dir.clone(),
        )?;

        let rpc_client = BlockingClient::new(&config.rpc_url);

        // NOTE: we could probably avoid creating a second validator
        // by making the one in `DiemDebugger` accessible publicly
        let validator = Box::new(JsonRpcDebuggerInterface::new(&config.rpc_url)?);
        Ok(PrefetchTransactionReplayer {
            config,
            validator,
            debugger,
            rpc_client,
        })
    }

    fn get_keys_read_for_tx(
        &self,
        live_state: &impl MoveResolver,
        tx: &Transaction,
        rw_analysis: &ReadWriteSetAnalysis,
    ) -> Result<Vec<ResourceKey>> {
        let signed_tx = match tx {
            Transaction::UserTransaction(u) => u,
            t => {
                warn!("cannot process tx {:?}, ignoring", t);
                return Ok(vec![]);
            }
        };

        // NOTE: we might need to do something about the transactions we do
        // not currently handle
        match signed_tx.payload() {
            TransactionPayload::ScriptFunction(_) => {
                rw_analysis.get_keys_read(signed_tx, live_state)
            }
            payload => {
                warn!("cannot process payload {:?}, ignoring", payload);
                Ok(vec![])
            }
        }
    }

    fn get_unique_addresses_from_keys(&self, key_reads: &[ResourceKey]) -> Vec<AccountAddress> {
        key_reads
            .iter()
            .map(|k| k.address)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }

    fn extract_account_state(&self, state_with_proof: &AccountStateWithProofView) -> AccountState {
        // NOTE: if this has a chance to fail, it might be better to change
        // the function to return Result<AccountState>
        let blob = state_with_proof.blob.as_ref().unwrap();
        let parsed_blob = bcs::from_bytes::<AccountStateBlob>(blob).unwrap();
        AccountState::try_from(&parsed_blob).unwrap()
    }

    fn fetch_accounts_storage(
        &self,
        addresses: &[AccountAddress],
    ) -> Result<Vec<AccountAddressWithState>> {
        let requests = addresses
            .iter()
            .map(|a| MethodRequest::get_account_state_with_proof(*a, None, None))
            .collect();

        let results = self
            .rpc_client
            .batch(requests)?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        let account_states: Vec<AccountAddressWithState> = results
            .into_iter()
            .zip(addresses.iter())
            .filter_map(|(r, a)| match r.into_inner() {
                MethodResponse::GetAccountStateWithProof(v) => {
                    let state = self.extract_account_state(&v);
                    Some(AccountAddressWithState { address: *a, state })
                }
                _ => None,
            })
            .collect();

        Ok(account_states)
    }

    fn get_addresses_read_by_txs(
        &self,
        txs: &[Transaction],
        replay_version: u64,
    ) -> Result<Vec<AccountAddress>> {
        // TODO: use dependency analysis to fetch the modules relevant
        // to the transactions rather than all the modules at address 0x1
        let modules = self
            .debugger
            .get_diem_framework_modules_at_version(replay_version, true)?;

        let mut keys = vec![];
        let rw_analysis = ReadWriteSetAnalysis::new(read_write_set::analyze(&modules)?);

        let live_state_view = DebuggerStateView::new(self.validator.as_ref(), replay_version);
        let live_storage = RemoteStorage::new(&live_state_view);

        for tx in txs.iter() {
            let new_keys = self.get_keys_read_for_tx(&live_storage, tx, &rw_analysis)?;
            keys.extend(new_keys);
        }
        Ok(self.get_unique_addresses_from_keys(&keys))
    }

    fn populate_storage_for_transactions(
        &self,
        txs: &[Transaction],
        version: Option<u64>,
    ) -> Result<()> {
        let replay_version = match version {
            Some(0) => 1,
            Some(v) => v,
            None => self.debugger.get_latest_version()?,
        };

        let addresses_read = self.get_addresses_read_by_txs(txs, replay_version)?;
        let accounts_states = self.fetch_accounts_storage(&addresses_read)?;
        for account in accounts_states {
            self.debugger
                .save_account_state(account.address, &account.state)?;
        }
        Ok(())
    }

    fn _execute_transactions_at<V: VMExecutor>(
        &self,
        state: &OnDiskStateViewReader,
        txs: Vec<Transaction>,
        version: Option<u64>,
    ) -> Result<Vec<TransactionOutput>> {
        self.populate_storage_for_transactions(&txs, version)?;
        V::execute_block(txs, state).map_err(|err| format_err!("Unexpected VM Error: {:?}", err))
    }

    fn cleanup_dirs(&self) -> Result<()> {
        let mut result = vec![];
        for dir in vec![&self.config.storage_dir, &self.config.build_dir].into_iter() {
            let res = fs::remove_dir_all(dir);
            result.push(res.map_err(|e| format_err!("could not remove {:?}: {}", dir, e)))
        }
        result.into_iter().collect()
    }

    pub fn execute_transactions_at<V: VMExecutor>(
        &self,
        txs: Vec<Transaction>,
        version: Option<u64>,
    ) -> Result<Vec<TransactionOutput>> {
        let mode = Mode::new(self.config.mode_type);
        let result = mode
            .prepare_state(
                self.config.build_dir.as_path(),
                self.config.storage_dir.as_path(),
            )
            .and_then(|view| {
                let state = OnDiskStateViewReader { view };
                self._execute_transactions_at::<V>(&state, txs, version)
            });
        self.cleanup_dirs()?;

        result
    }

    // NOTE: this is mostly taken from the diem-transaction-replay crate
    // we could fairly easily avoid duplication if desired
    pub fn execute_transactions<V: VMExecutor>(
        &self,
        mut txns: Vec<Transaction>,
        version: Option<Version>,
        mut limit: u64,
    ) -> Result<Vec<TransactionOutput>> {
        let mut ret = vec![];
        let mut begin = 0;
        while limit != 0 && !txns.is_empty() {
            info!(
                "Starting epoch execution at {:?}, {:?} transactions remaining",
                begin, limit
            );
            let mut epoch_result = self.execute_transactions_at::<V>(txns.clone(), version)?;
            begin += epoch_result.len() as u64;
            limit -= epoch_result.len() as u64;
            txns = txns.split_off(epoch_result.len());
            ret.append(&mut epoch_result);
        }
        Ok(ret)
    }

    pub fn execute_past_transactions<V: VMExecutor>(
        &self,
        begin: Version,
        limit: u64,
    ) -> Result<Vec<TransactionOutput>> {
        let txns = self.validator.get_committed_transactions(begin, limit)?;
        self.execute_transactions::<V>(txns, Some(begin), limit)
    }

    pub fn execute_account_transactions<V: VMExecutor>(
        &self,
        account: AccountAddress,
        begin: Version,
        limit: u64,
    ) -> Result<Vec<TransactionOutput>> {
        let txns = self
            .validator
            .get_account_transactions(account, begin, limit)?;
        self.execute_transactions::<V>(txns, Some(begin), limit)
    }

    pub fn execute_serialized_user_transactions<V: VMExecutor>(
        &self,
        txs_path: PathBuf,
    ) -> Result<Vec<TransactionOutput>> {
        let file = File::open(txs_path)?;
        let lines = BufReader::new(file).lines();
        let mut txns = vec![];
        for line in lines {
            let raw_tx = hex::decode(line?)?;
            let tx: SignedTransaction = bcs::from_bytes(&raw_tx)?;
            txns.push(Transaction::UserTransaction(tx));
        }
        let limit = txns.len() as u64;
        self.execute_transactions::<V>(txns, None, limit)
    }
}

pub fn run_cli<V: VMExecutor>(
    args: PrefetchedReplayCLI,
    mut build_dir: PathBuf,
    mut storage_dir: PathBuf,
    mode_type: ModeType,
) -> Result<()> {
    if build_dir.is_relative() {
        build_dir = std::env::temp_dir().join(build_dir);
    }

    if storage_dir.is_relative() {
        storage_dir = std::env::temp_dir().join(storage_dir);
    }

    let config = PrefetchTransactionReplayerConfig {
        build_dir,
        storage_dir,
        mode_type,
        rpc_url: args.rpc_url,
    };

    let replayer = PrefetchTransactionReplayer::from_config(config)?;

    let outputs = match args.cmd {
        Command::ReplayTransactions { start, limit } => {
            replayer.execute_past_transactions::<V>(start, limit)
        }
        Command::ReplayAccountTransactions {
            account,
            start,
            limit,
        } => replayer.execute_account_transactions::<V>(account, start, limit),
        Command::ExecuteSerializedTransactions { txs_path } => {
            replayer.execute_serialized_user_transactions::<V>(txs_path)
        }
    };

    outputs
        .and_then(|v| {
            serde_json::to_string(&v).map_err(|e| format_err!("could not format to json: {}", e))
        })
        .map(|v| println!("{}", v))
}
