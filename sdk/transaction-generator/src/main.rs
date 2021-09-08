// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This crates provides a CLI tool for generating transaction for development purposes.
//! All the commands require a Diem node to be running and require access to the mint key.
//! ## Available commands
//!
//! * `create-accounts` - Create `n` new accounts and mints `amount` for them if desired
//!   ```
//!   # without minting
//!   cargo run -- --mint-key /path/to/mint.key create-accounts -n 2
//!   # minting 5 XUS
//!   cargo run -- --mint-key /path/to/mint.key create-accounts -n 2 --amount 5
//!   ```
//! * `execute-mint-txs` - Execute mint transactions for given addresses
//!   ```
//!   cargo run -- --mint-key /path/to/mint.key execute-mint-txs --amount 5 --addresses ADDR2 ADDR2
//!   ```
//! * `generate-mint-txs` - Same as execute mint transactions but saves the raw transactions to `output`
//!   instead of executing it
//!   ```
//!   cargo run -- --mint-key /path/to/mint.key generate-mint-txs --amount 5 --addresses ADDR2 ADDR2 --output /path/to/output.hex
//!   ```

use std::{fs::File, io::Write, path::PathBuf};

use anyhow::Result;

use diem_client::AccountAddress;
use diem_logger::Logger;
use diem_transaction_generator::TxGenerator;
use diem_types::chain_id::ChainId;
use structopt::StructOpt;

fn parse_unscaled_value(value: &str) -> Result<u64> {
    let fvalue: f64 = value.parse()?;
    let scaled = fvalue * 10f64.powf(6.0);
    Ok(scaled.round() as u64)
}

#[derive(Debug, StructOpt)]
#[structopt(
    about = "Generate and execute transactions to a remote node",
    rename_all = "kebab-case"
)]
pub struct Args {
    #[structopt(long, default_value = "http://localhost:8080")]
    rpc_url: String,

    #[structopt(long)]
    mint_key: String,

    #[structopt(long, default_value = "TESTING")]
    chain_id: ChainId,

    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    /// Create new accounts
    #[structopt(name = "create-accounts")]
    CreateAccounts {
        #[structopt(short = "n")]
        number: usize,

        #[structopt(long, parse(try_from_str = parse_unscaled_value), default_value = "0")]
        amount: u64,
    },
    #[structopt(name = "execute-mint-txs")]
    ExecuteMintTxs {
        #[structopt(long, parse(try_from_str = parse_unscaled_value), default_value = "0")]
        amount: u64,

        #[structopt(long)]
        addresses: Vec<AccountAddress>,
    },
    #[structopt(name = "generate-mint-txs")]
    GenerateMintTxs {
        #[structopt(long, parse(try_from_str = parse_unscaled_value), default_value = "0")]
        amount: u64,

        #[structopt(long)]
        addresses: Vec<AccountAddress>,

        #[structopt(long)]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    Logger::builder().build();

    let args = Args::from_args();

    let mut generator = TxGenerator::new(args.rpc_url, &args.mint_key, args.chain_id);

    match args.cmd {
        Command::CreateAccounts { number, amount } => {
            let accounts = generator.create_seed_accounts(number).await?;

            for account in accounts.iter() {
                println!("{}", account.address().to_hex());
            }

            let addresses: Vec<_> = accounts.iter().map(|a| a.address()).collect();
            if amount > 0 {
                generator.mint_to_accounts(&addresses, amount).await?;
            }
        }
        Command::ExecuteMintTxs { amount, addresses } => {
            generator.mint_to_accounts(&addresses, amount).await?;
        }
        Command::GenerateMintTxs {
            amount,
            addresses,
            output,
        } => {
            let txs = generator
                .gen_mint_to_accounts_txs(&addresses, amount)
                .await?;
            let mut file = File::create(&output)?;
            for tx in txs.iter() {
                let serialized = hex::encode(bcs::to_bytes(tx)?);
                writeln!(&mut file, "{}", serialized)?;
            }
        }
    }

    Ok(())
}
