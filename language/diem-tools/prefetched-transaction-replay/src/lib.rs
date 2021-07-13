// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::convert::TryFrom;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, format_err, Result};
use diem_client::{
    views::AccountStateWithProofView, AccountAddress, BlockingClient, MethodRequest, MethodResponse,
};
use diem_read_write_set::ReadWriteSetAnalysis;
use diem_state_view::StateView;
use diem_transaction_replay::DiemDebugger;
use diem_types::access_path::AccessPath;
use diem_types::transaction::{TransactionOutput, Version};
use diem_types::{
    account_state::AccountState, account_state_blob::AccountStateBlob, transaction::Transaction,
};
use diem_validator_interface::{DiemValidatorInterface, JsonRpcDebuggerInterface};
use diem_vm::VMExecutor;
use move_cli::sandbox::utils::{
    mode::{Mode, ModeType},
    on_disk_state_view::OnDiskStateView,
};
use move_core_types::language_storage::ResourceKey;

use structopt::StructOpt;

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
}

#[derive(Debug, StructOpt)]
#[structopt(
    about = "Replay transactions using state prefetching",
    rename_all = "kebab-case"
)]
pub struct PrefetchedReplayCLI {
    #[structopt(long, default_value = "http://localhost:8080")]
    rpc_url: String,

    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    /// Replay transactions starting from version `start` to `start + limit`.
    #[structopt(name = "replay-transactions")]
    ReplayTransactions { start: Version, limit: u64 },
}

pub struct PrefetchTransactionReplayer {
    config: PrefetchTransactionReplayerConfig,
    validator: Box<dyn DiemValidatorInterface>,
    debugger: DiemDebugger,
    rpc_client: BlockingClient,
}

impl StateView for OnDiskStateViewReader {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        access_path.get_struct_tag().map_or(Ok(None), |tag| {
            self.view.get_resource_bytes(access_path.address, tag)
        })
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
        state: &OnDiskStateViewReader,
        tx: &Transaction,
        rw_analysis: &ReadWriteSetAnalysis,
    ) -> Result<Vec<ResourceKey>> {
        let signed_tx = match tx {
            Transaction::UserTransaction(u) => u,
            _ => bail!("can only process user transactions"),
        };

        rw_analysis.get_keys_read(signed_tx, &state.view)
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
        let parsed_blob = bcs::from_bytes::<AccountStateBlob>(&blob).unwrap();
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
        state: &OnDiskStateViewReader,
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
        for tx in txs.iter() {
            let new_keys = self.get_keys_read_for_tx(state, tx, &rw_analysis)?;
            keys.extend(new_keys);
        }
        Ok(self.get_unique_addresses_from_keys(&keys))
    }

    fn populate_storage_for_transactions(
        &self,
        state: &OnDiskStateViewReader,
        txs: &[Transaction],
        version: Option<u64>,
    ) -> Result<()> {
        let replay_version = match version {
            Some(v) => v,
            None => self.debugger.get_latest_version()?,
        };

        let addresses_read = self.get_addresses_read_by_txs(state, txs, replay_version)?;
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
        self.populate_storage_for_transactions(state, &txs, version)?;
        V::execute_block(txs, state).map_err(|err| format_err!("Unexpected VM Error: {:?}", err))
    }

    fn cleanup_dirs(&self) -> Result<()> {
        let dirs_to_clean = vec![&self.config.storage_dir, &self.config.build_dir];
        dirs_to_clean.into_iter().fold(Ok(()), |acc, dir| {
            let res = fs::remove_dir_all(dir);
            acc.and(res.map_err(|e| format_err!("could not remove {:?}: {}", dir, e)))
        })
    }

    pub fn execute_transactions_at<V: VMExecutor>(
        &self,
        txs: Vec<Transaction>,
        version: Option<u64>,
    ) -> Result<Vec<TransactionOutput>> {
        let mode = Mode::new(ModeType::Bare);
        let result = mode
            .prepare_state(&self.config.build_dir, &self.config.storage_dir)
            .and_then(|view| {
                let state = OnDiskStateViewReader { view };
                self._execute_transactions_at::<V>(&state, txs, version)
            });
        self.cleanup_dirs()?;

        result
    }

    // NOTE: this is mostly taken from the diem-transaction-replay crate
    // we could fairly easily avoid duplication if desired
    pub fn execute_past_transactions<V: VMExecutor>(
        &self,
        mut begin: Version,
        mut limit: u64,
    ) -> Result<Vec<TransactionOutput>> {
        let mut txns = self.validator.get_committed_transactions(begin, limit)?;
        let mut ret = vec![];
        while limit != 0 {
            println!(
                "Starting epoch execution at {:?}, {:?} transactions remaining",
                begin, limit
            );
            let mut epoch_result = self.execute_transactions_at::<V>(txns.clone(), Some(begin))?;
            begin += epoch_result.len() as u64;
            limit -= epoch_result.len() as u64;
            txns = txns.split_off(epoch_result.len());
            ret.append(&mut epoch_result);
        }
        Ok(ret)
    }
}

pub fn run_cli<V: VMExecutor>(
    args: PrefetchedReplayCLI,
    build_dir: PathBuf,
    storage_dir: PathBuf,
) -> Result<()> {
    let config = PrefetchTransactionReplayerConfig {
        build_dir,
        storage_dir,
        rpc_url: args.rpc_url,
    };

    let replayer = PrefetchTransactionReplayer::from_config(config)?;

    match args.cmd {
        Command::ReplayTransactions { start, limit } => replayer
            .execute_past_transactions::<V>(start, limit)
            .map(|v| println!("{:#?}", v)),
    }
}
