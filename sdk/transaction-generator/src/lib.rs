// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{format_err, Result};
use diem_client::{Client as JsonRpcClient, MethodRequest, SignedTransaction};
use diem_logger::*;
use diem_sdk::{
    crypto::ed25519::Ed25519PrivateKey,
    transaction_builder::{Currency, TransactionFactory},
    types::{AccountKey, LocalAccount},
};
use diem_types::{
    account_address::AccountAddress,
    account_config::{testnet_dd_account_address, treasury_compliance_account_address},
    chain_id::ChainId,
};
use itertools::zip;
use rand::{
    rngs::{OsRng, StdRng},
    Rng, SeedableRng,
};
use std::{cmp::min, path::PathBuf};

use std::{
    env, slice,
    time::{Duration, Instant},
};
use tokio::time;

const MAX_TXN_BATCH_SIZE: usize = 100; // Max transactions per account in mempool
                                       // Please make 'MAX_CHILD_VASP_NUM' consistency with 'MAX_CHILD_ACCOUNTS' constant under VASP.move
const TXN_EXPIRATION_SECONDS: i64 = 150;
const TXN_MAX_WAIT: Duration = Duration::from_secs(TXN_EXPIRATION_SECONDS as u64 + 30);

pub async fn execute_and_wait_transactions(
    client: &JsonRpcClient,
    account: &mut LocalAccount,
    txn: &[SignedTransaction],
) -> Result<()> {
    debug!(
        "[{:?}] Submitting transactions {} - {} for {}",
        client,
        account.sequence_number() - txn.len() as u64,
        account.sequence_number(),
        account.address()
    );
    for request in txn {
        diem_retrier::retry_async(diem_retrier::fixed_retry_strategy(5_000, 20), || {
            let request = request.clone();
            let c = client.clone();
            let client_name = format!("{:?}", client);
            Box::pin(async move {
                let txn_str = format!("{}::{}", request.sender(), request.sequence_number());
                debug!("Submitting txn {}", txn_str);
                let resp = c.submit(&request).await;
                debug!("txn {} status: {:?}", txn_str, resp);

                resp.map_err(|e| format_err!("[{}] Failed to submit request: {:?}", client_name, e))
            })
        })
        .await?;
    }
    let r = wait_for_accounts_sequence(client, slice::from_mut(account))
        .await
        .map_err(|_| format_err!("Mint transactions were not committed before expiration"));
    debug!(
        "[{:?}] Account {} is at sequence number {} now",
        client,
        account.address(),
        account.sequence_number()
    );
    r
}

async fn wait_for_accounts_sequence(
    client: &JsonRpcClient,
    accounts: &mut [LocalAccount],
) -> Result<(), Vec<(AccountAddress, u64)>> {
    let deadline = Instant::now() + TXN_MAX_WAIT;
    let addresses: Vec<_> = accounts.iter().map(|d| d.address()).collect();
    loop {
        match query_sequence_numbers(client, &addresses).await {
            Err(e) => {
                info!(
                    "Failed to query ledger info on accounts {:?} for instance {:?} : {:?}",
                    addresses, client, e
                );
                time::sleep(Duration::from_millis(300)).await;
            }
            Ok(sequence_numbers) => {
                if is_sequence_equal(accounts, &sequence_numbers) {
                    break;
                }
                let mut uncommitted = vec![];
                if Instant::now() > deadline {
                    for (account, sequence_number) in zip(accounts, &sequence_numbers) {
                        if account.sequence_number() != *sequence_number {
                            warn!("Wait deadline exceeded for account {}, expected sequence {}, got from server: {}", account.address(), account.sequence_number(), sequence_number);
                            uncommitted.push((account.address(), *sequence_number));
                            *account.sequence_number_mut() = *sequence_number;
                        }
                    }
                    return Err(uncommitted);
                }
            }
        }
        time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

fn is_sequence_equal(accounts: &[LocalAccount], sequence_numbers: &[u64]) -> bool {
    for (account, sequence_number) in zip(accounts, sequence_numbers) {
        if *sequence_number != account.sequence_number() {
            return false;
        }
    }
    true
}

async fn query_sequence_numbers(
    client: &JsonRpcClient,
    addresses: &[AccountAddress],
) -> Result<Vec<u64>> {
    let mut result = vec![];
    for addresses_batch in addresses.chunks(20) {
        let resp = client
            .batch(
                addresses_batch
                    .iter()
                    .map(|a| MethodRequest::get_account(*a))
                    .collect(),
            )
            .await?
            .into_iter()
            .map(|r| r.map_err(anyhow::Error::new))
            .map(|r| r.map(|response| response.into_inner().unwrap_get_account()))
            .collect::<Result<Vec<_>>>()
            .map_err(|e| format_err!("[{:?}] get_accounts failed: {:?} ", client, e))?;

        for item in resp.into_iter() {
            result.push(
                item.ok_or_else(|| format_err!("account does not exist"))?
                    .sequence_number,
            );
        }
    }
    Ok(result)
}

fn gen_random_accounts(num_accounts: usize) -> Vec<LocalAccount> {
    let seed: [u8; 32] = OsRng.gen();
    let mut rng = StdRng::from_seed(seed);
    (0..num_accounts)
        .map(|_| LocalAccount::generate(&mut rng))
        .collect()
}

fn gen_account_creation_txn_requests(
    creation_account: &mut LocalAccount,
    accounts: &[LocalAccount],
    chain_id: ChainId,
) -> Vec<SignedTransaction> {
    accounts
        .iter()
        .map(|account| gen_create_account_txn_request(creation_account, account, chain_id))
        .collect()
}

fn gen_create_account_txn_request(
    creation_account: &mut LocalAccount,
    account: &LocalAccount,
    chain_id: ChainId,
) -> SignedTransaction {
    creation_account.sign_with_transaction_builder(
        TransactionFactory::new(chain_id).create_parent_vasp_account(
            Currency::XUS,
            0,
            account.authentication_key(),
            "",
            false,
        ),
    )
}

fn gen_mint_txn_requests(
    sending_account: &mut LocalAccount,
    addresses: &[AccountAddress],
    amount: u64,
    chain_id: ChainId,
) -> Vec<SignedTransaction> {
    addresses
        .iter()
        .map(|address| gen_mint_txn_request(sending_account, address, amount, chain_id))
        .collect()
}

fn gen_mint_txn_request(
    sender: &mut LocalAccount,
    receiver: &AccountAddress,
    num_coins: u64,
    chain_id: ChainId,
) -> SignedTransaction {
    sender.sign_with_transaction_builder(TransactionFactory::new(chain_id).peer_to_peer(
        Currency::XUS,
        *receiver,
        num_coins,
    ))
}

pub struct TxGenerator {
    mint_key: Ed25519PrivateKey,
    rpc_client: JsonRpcClient,
    chain_id: ChainId,
}

impl TxGenerator {
    pub fn new<T: Into<PathBuf>>(rpc_url: String, mint_key_path: T, chain_id: ChainId) -> Self {
        let mint_key = generate_key::load_key(mint_key_path.into());
        let rpc_client = JsonRpcClient::new(&rpc_url);
        TxGenerator {
            mint_key,
            rpc_client,
            chain_id,
        }
    }

    fn account_key(&self) -> AccountKey {
        AccountKey::from_private_key(self.mint_key.clone())
    }

    async fn load_account_with_mint_key(&self, address: AccountAddress) -> Result<LocalAccount> {
        let sequence_number = query_sequence_numbers(&self.rpc_client, &[address])
            .await
            .map_err(|e| {
                format_err!(
                    "query_sequence_numbers for account {} failed: {}",
                    address,
                    e
                )
            })?[0];
        Ok(LocalAccount::new(
            address,
            self.account_key(),
            sequence_number,
        ))
    }

    pub async fn load_faucet_account(&self) -> Result<LocalAccount> {
        self.load_account_with_mint_key(testnet_dd_account_address())
            .await
    }

    pub async fn load_tc_account(&self) -> Result<LocalAccount> {
        self.load_account_with_mint_key(treasury_compliance_account_address())
            .await
    }

    pub async fn gen_create_seed_accounts_txs(
        &mut self,
        num_new_accounts: usize,
    ) -> Result<(Vec<LocalAccount>, Vec<SignedTransaction>)> {
        let mut creation_account = self.load_tc_account().await?;
        let accounts = gen_random_accounts(num_new_accounts);
        let transactions =
            gen_account_creation_txn_requests(&mut creation_account, &accounts, self.chain_id);
        Ok((accounts, transactions))
    }

    /// Create `num_new_accounts`. Return Vec of created accounts
    pub async fn create_seed_accounts(
        &mut self,
        num_new_accounts: usize,
    ) -> Result<Vec<LocalAccount>> {
        let mut creation_account = self.load_tc_account().await?;
        let mut i = 0;
        let accounts = gen_random_accounts(num_new_accounts);
        while i < num_new_accounts {
            let batch_size = min(MAX_TXN_BATCH_SIZE, num_new_accounts - i);
            let create_requests = gen_account_creation_txn_requests(
                &mut creation_account,
                &accounts[i..i + batch_size],
                self.chain_id,
            );
            execute_and_wait_transactions(
                &self.rpc_client,
                &mut creation_account,
                &create_requests,
            )
            .await?;
            i += batch_size;
        }
        Ok(accounts)
    }

    pub async fn gen_mint_to_accounts_txs(
        &self,
        addresses: &[AccountAddress],
        diem_per_new_account: u64,
    ) -> Result<Vec<SignedTransaction>> {
        let mut minting_account = self.load_faucet_account().await?;
        let mint_requests = gen_mint_txn_requests(
            &mut minting_account,
            addresses,
            diem_per_new_account,
            self.chain_id,
        );
        Ok(mint_requests)
    }

    /// Mint `diem_per_new_account` from faucet to each account in `accounts`.
    pub async fn mint_to_accounts(
        &self,
        addresses: &[AccountAddress],
        diem_per_new_account: u64,
    ) -> Result<()> {
        let mut minting_account = self.load_faucet_account().await?;
        let mut left = addresses;
        while !left.is_empty() {
            let batch_size = min(MAX_TXN_BATCH_SIZE, left.len());
            let (batch_addresses, rest) = left.split_at(batch_size);
            let mint_requests = gen_mint_txn_requests(
                &mut minting_account,
                batch_addresses,
                diem_per_new_account,
                self.chain_id,
            );
            execute_and_wait_transactions(&self.rpc_client, &mut minting_account, &mint_requests)
                .await?;
            left = rest;
        }
        Ok(())
    }
}
