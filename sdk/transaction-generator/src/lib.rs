use anyhow::{format_err, Result};
use diem_client::{Client as JsonRpcClient, MethodRequest, SignedTransaction};
use diem_logger::*;
use diem_sdk::{
    transaction_builder::{Currency, TransactionFactory},
    types::{AccountKey, LocalAccount},
};
use diem_types::{
    account_address::AccountAddress, chain_id::ChainId,
    transaction::authenticator::AuthenticationKey,
};
use itertools::zip;
use rand::{
    rngs::{OsRng, StdRng},
    Rng, SeedableRng,
};
use std::cmp::min;

use std::{
    env, slice,
    time::{Duration, Instant},
};
use tokio::time;

const MAX_TXN_BATCH_SIZE: usize = 100; // Max transactions per account in mempool
                                       // Please make 'MAX_CHILD_VASP_NUM' consistency with 'MAX_CHILD_ACCOUNTS' constant under VASP.move
const MAX_CHILD_VASP_NUM: usize = 65536;
const MAX_VASP_ACCOUNT_NUM: usize = 16;
const TXN_EXPIRATION_SECONDS: i64 = 150;
const TXN_MAX_WAIT: Duration = Duration::from_secs(TXN_EXPIRATION_SECONDS as u64 + 30);
const MAX_TXNS: u64 = 1_000_000;
const SEND_AMOUNT: u64 = 1;

pub async fn execute_and_wait_transactions(
    client: &mut JsonRpcClient,
    account: &mut LocalAccount,
    txn: Vec<SignedTransaction>,
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

/// Create `num_new_accounts` by transferring diem from `source_account`. Return Vec of created
/// accounts
async fn create_new_accounts(
    mut source_account: LocalAccount,
    num_new_accounts: usize,
    diem_per_new_account: u64,
    max_num_accounts_per_batch: u64,
    mut client: JsonRpcClient,
    chain_id: ChainId,
    reuse_account: bool,
    mut rng: StdRng,
) -> Result<Vec<LocalAccount>> {
    let mut i = 0;
    let mut accounts = vec![];
    while i < num_new_accounts {
        let batch_size = min(
            max_num_accounts_per_batch as usize,
            min(MAX_TXN_BATCH_SIZE, num_new_accounts - i),
        );
        let mut batch = if reuse_account {
            info!("loading {} accounts if they exist", batch_size);
            gen_reusable_accounts(&client, batch_size, &mut rng).await?
        } else {
            gen_random_accounts(batch_size)
        };
        let requests = gen_create_child_txn_requests(
            &mut source_account,
            &batch,
            diem_per_new_account,
            chain_id,
        );
        execute_and_wait_transactions(&mut client, &mut source_account, requests).await?;
        i += batch.len();
        accounts.append(&mut batch);
    }
    Ok(accounts)
}

/// Create `num_new_accounts`. Return Vec of created accounts
async fn create_seed_accounts(
    creation_account: &mut LocalAccount,
    num_new_accounts: usize,
    max_num_accounts_per_batch: u64,
    mut client: JsonRpcClient,
    chain_id: ChainId,
) -> Result<Vec<LocalAccount>> {
    let mut i = 0;
    let mut accounts = vec![];
    while i < num_new_accounts {
        let mut batch = gen_random_accounts(min(
            max_num_accounts_per_batch as usize,
            min(MAX_TXN_BATCH_SIZE, num_new_accounts - i),
        ));
        let create_requests = gen_account_creation_txn_requests(creation_account, &batch, chain_id);
        execute_and_wait_transactions(&mut client, creation_account, create_requests).await?;
        i += batch.len();
        accounts.append(&mut batch);
    }
    Ok(accounts)
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

async fn gen_reusable_account(client: &JsonRpcClient, rng: &mut StdRng) -> Result<LocalAccount> {
    let account_key = AccountKey::generate(rng);
    let address = account_key.authentication_key().derived_address();
    let sequence_number = match query_sequence_numbers(client, &[address]).await {
        Ok(v) => v[0],
        Err(_) => 0,
    };
    Ok(LocalAccount::new(address, account_key, sequence_number))
}

async fn gen_reusable_accounts(
    client: &JsonRpcClient,
    num_accounts: usize,
    rng: &mut StdRng,
) -> Result<Vec<LocalAccount>> {
    let mut vasp_accounts = vec![];
    let mut i = 0;
    while i < num_accounts {
        vasp_accounts.push(gen_reusable_account(client, rng).await?);
        i += 1;
    }
    Ok(vasp_accounts)
}

fn gen_random_accounts(num_accounts: usize) -> Vec<LocalAccount> {
    let seed: [u8; 32] = OsRng.gen();
    let mut rng = StdRng::from_seed(seed);
    (0..num_accounts)
        .map(|_| LocalAccount::generate(&mut rng))
        .collect()
}

fn gen_create_child_txn_request(
    sender: &mut LocalAccount,
    receiver_auth_key: AuthenticationKey,
    num_coins: u64,
    chain_id: ChainId,
) -> SignedTransaction {
    sender.sign_with_transaction_builder(
        TransactionFactory::new(chain_id).create_child_vasp_account(
            Currency::XUS,
            receiver_auth_key,
            false,
            num_coins,
        ),
    )
}

fn gen_create_child_txn_requests(
    source_account: &mut LocalAccount,
    accounts: &[LocalAccount],
    amount: u64,
    chain_id: ChainId,
) -> Vec<SignedTransaction> {
    accounts
        .iter()
        .map(|account| {
            gen_create_child_txn_request(
                source_account,
                account.authentication_key(),
                amount,
                chain_id,
            )
        })
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

/// Mint `diem_per_new_account` from `minting_account` to each account in `accounts`.
async fn mint_to_new_accounts(
    minting_account: &mut LocalAccount,
    accounts: &[LocalAccount],
    diem_per_new_account: u64,
    max_num_accounts_per_batch: u64,
    mut client: JsonRpcClient,
    chain_id: ChainId,
) -> Result<()> {
    let mut left = accounts;
    let mut i = 0;
    let num_accounts = accounts.len();
    while !left.is_empty() {
        let batch_size = OsRng.gen::<usize>()
            % min(
                max_num_accounts_per_batch as usize,
                min(MAX_TXN_BATCH_SIZE, num_accounts - i),
            );
        let (to_batch, rest) = left.split_at(batch_size + 1);
        let mint_requests =
            gen_mint_txn_requests(minting_account, to_batch, diem_per_new_account, chain_id);
        execute_and_wait_transactions(&mut client, minting_account, mint_requests).await?;
        i += to_batch.len();
        left = rest;
    }
    Ok(())
}

fn gen_mint_txn_requests(
    sending_account: &mut LocalAccount,
    accounts: &[LocalAccount],
    amount: u64,
    chain_id: ChainId,
) -> Vec<SignedTransaction> {
    accounts
        .iter()
        .map(|account| gen_mint_txn_request(sending_account, &account.address(), amount, chain_id))
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
