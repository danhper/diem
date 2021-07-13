// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use diem_logger::Logger;
use diem_prefetched_transaction_replay::PrefetchedReplayCLI;
use diem_vm::DiemVM;
use move_cli::{Command as MoveCLICommand, Move};
use move_core_types::errmap::ErrorMapping;
use structopt::StructOpt;

#[derive(StructOpt)]
pub struct DfCli {
    #[structopt(flatten)]
    move_args: Move,

    #[structopt(subcommand)]
    cmd: DfCommands,
}

#[derive(StructOpt)]
pub enum DfCommands {
    #[structopt(flatten)]
    MoveCLICommand(MoveCLICommand),
    // extra commands available only in df-cli can be added below
    #[structopt(name = "prefetched-replay")]
    PrefetchedReplayCommand(PrefetchedReplayCLI),
}

fn main() -> Result<()> {
    Logger::builder().build();

    let error_descriptions: ErrorMapping =
        bcs::from_bytes(diem_framework_releases::current_error_descriptions())?;
    let args = DfCli::from_args();
    match args.cmd {
        DfCommands::MoveCLICommand(cmd) => move_cli::run_cli(
            diem_vm::natives::diem_natives(),
            &error_descriptions,
            &args.move_args,
            &cmd,
        ),
        DfCommands::PrefetchedReplayCommand(cmd) => {
            diem_prefetched_transaction_replay::run_cli::<DiemVM>(
                cmd,
                args.move_args.build_dir,
                args.move_args.storage_dir,
                args.move_args.mode,
            )
        }
    }
}
