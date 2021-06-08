// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    cargo::{build_args::BuildArgs, selected_package::SelectedPackageArgs, CargoCommand},
    context::XContext,
    utils::project_root,
    Result,
};
use anyhow::{anyhow, Error};
use log::info;
use std::{
    ffi::OsString,
    fs::create_dir_all,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Args {
    #[structopt(flatten)]
    pub(crate) package_args: SelectedPackageArgs,
    #[structopt(long, short)]
    /// Skip running expensive diem testsuite integration tests
    unit: bool,
    #[structopt(long)]
    /// Only run doctests
    doc: bool,
    #[structopt(flatten)]
    pub(crate) build_args: BuildArgs,
    #[structopt(long)]
    /// Do not fast fail the run if tests (or test executables) fail
    no_fail_fast: bool,
    #[structopt(long)]
    /// Do not run tests, only compile the test executables
    no_run: bool,
    #[structopt(long, parse(from_os_str))]
    /// Directory to output HTML coverage report (using grcov)
    html_cov_dir: Option<PathBuf>,
    #[structopt(long, parse(from_os_str))]
    /// Directory to output lcov coverage html (using grcov -> lcov.info -> html using genhtml).
    /// Only useful if you want the lcov.info file produced in the path.  Requires that lcov be installed and on PATH.
    html_lcov_dir: Option<PathBuf>,
    #[structopt(name = "TESTNAME", parse(from_os_str))]
    testname: Option<OsString>,
    #[structopt(name = "ARGS", parse(from_os_str), last = true)]
    args: Vec<OsString>,
}

pub fn run(mut args: Args, xctx: XContext) -> Result<()> {
    let config = xctx.config();

    let mut packages = args.package_args.to_selected_packages(&xctx)?;
    if args.unit {
        packages.add_excludes(config.system_tests().iter().map(|(p, _)| p.as_str()));
    }

    args.args.extend(args.testname.clone());

    let generate_coverage = args.html_cov_dir.is_some() || args.html_lcov_dir.is_some();

    let env_vars: &[(&str, Option<&str>)] = if generate_coverage {
        if !xctx
            .installer()
            .install_via_rustup_if_needed("llvm-tools-preview")
        {
            return Err(anyhow!("Could not install llvm-tools-preview"));
        }
        if !xctx.installer().install_via_cargo_if_needed("grcov") {
            return Err(anyhow!("Could not install grcov"));
        }
        let build_env_vars = &[
            // A way to use -Z (unstable) flags with the stable compiler. See below.
            ("RUSTC_BOOTSTRAP", Some("1")),
            // Recommend flags for use with grcov, with these flags removed: -Copt-level=0, -Clink-dead-code.
            // for more info see:  https://github.com/mozilla/grcov#example-how-to-generate-gcda-fiels-for-a-rust-project
            ("RUSTFLAGS", Some("-Zinstrument-coverage")),
            ("RUST_MIN_STACK", Some("8388608")),
        ];
        //info!("Running \"cargo clean\" before collecting coverage");
        //let mut clean_cmd = Command::new("cargo");
        //clean_cmd.arg("clean");
        //clean_cmd.output()?;
        info!("Performing a seperate \"cargo build\" before running tests and collecting coverage");
        let mut direct_args = Vec::new();
        args.build_args.add_args(&mut direct_args);
        let mut build = CargoCommand::Build {
            cargo_config: xctx.config().cargo_config(),
            direct_args: direct_args.as_slice(),
            args: &args.args,
            env: build_env_vars,
        };
        build.run_on_packages(&packages);

        &[
            // A way to use -Z (unstable) flags with the stable compiler. See below.
            ("RUSTC_BOOTSTRAP", Some("1")),
            // Recommend flags for use with grcov, with these flags removed: -Copt-level=0, -Clink-dead-code.
            // for more info see:  https://github.com/mozilla/grcov#example-how-to-generate-gcda-fiels-for-a-rust-project
            ("RUSTFLAGS", Some("-Zinstrument-coverage")),
            // Recommend setting for grcov, avoids using the cargo cache.
            //("CARGO_INCREMENTAL", Some("0")),
            //determines how to tie the coverage data back to source, one per execution.
            ("LLVM_PROFILE_FILE", Some("/tmp/xtest.profraw")), // the name should change if we have multiple runs.
            // language/ir-testsuite's tests will stack overflow without this setting.
            ("RUST_MIN_STACK", Some("8388608")),
        ]
    } else {
        &[]
    };

    let mut direct_args = Vec::new();
    args.build_args.add_args(&mut direct_args);
    if args.no_run {
        direct_args.push(OsString::from("--no-run"));
    };
    if args.no_fail_fast {
        direct_args.push(OsString::from("--no-fail-fast"));
    };
    if args.doc {
        direct_args.push(OsString::from("--doc"));
    }

    let cmd = CargoCommand::Test {
        cargo_config: xctx.config().cargo_config(),
        direct_args: direct_args.as_slice(),
        args: &args.args,
        env: &env_vars,
    };

    let cmd_result = cmd.run_on_packages(&packages);

    if !args.no_fail_fast && cmd_result.is_err() {
        return cmd_result;
    }

    if let Some(html_cov_dir) = &args.html_cov_dir {
        create_dir_all(&html_cov_dir)?;
        let html_cov_path = &html_cov_dir.canonicalize()?;
        info!("created {}", &html_cov_path.to_string_lossy());
        exec_grcov(&html_cov_path)?;
    }
    if let Some(html_lcov_dir) = &args.html_lcov_dir {
        create_dir_all(&html_lcov_dir)?;
        let html_lcov_path = &html_lcov_dir.canonicalize()?;
        info!("created {}", &html_lcov_path.to_string_lossy());
        exec_lcov(&html_lcov_path)?;
        exec_lcov_genhtml(&html_lcov_path)?;
    }
    cmd_result
}

fn exec_lcov_genhtml(html_lcov_path: &Path) -> Result<()> {
    let mut genhtml = Command::new("genhtml");
    let mut lcov_file_path = PathBuf::new();
    lcov_file_path.push(html_lcov_path);
    lcov_file_path.push("lcov.info");
    genhtml
        .current_dir(project_root())
        .arg("-o")
        .arg(html_lcov_path)
        .arg("--show-details")
        .arg("--highlight")
        .arg("--ignore-errors")
        .arg("source")
        .arg("--legend")
        //TODO: Paths seem to be a thing
        .arg(lcov_file_path);
    info!("Build grcov lcov.info file");
    info!("{:?}", genhtml);
    genhtml.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    if let Some(err) = genhtml.output().err() {
        Err(Error::new(err).context("Failed to generate html output from lcov.info"))
    } else {
        Ok(())
    }
}

fn exec_lcov(html_lcov_path: &Path) -> Result<()> {
    let debug_dir = project_root().join("target/debug/");
    let mut lcov_file_path = PathBuf::new();
    lcov_file_path.push(html_lcov_path);
    lcov_file_path.push("lcov.info");
    let mut lcov_file = Command::new("grcov");
    lcov_file
        .current_dir(project_root())
        //output file from coverage: gcda files
        .arg(debug_dir.as_os_str())
        //source code location
        .arg("-s")
        .arg(project_root().as_os_str())
        //html output
        .arg("-t")
        .arg("lcov")
        .arg("--llvm")
        .arg("--branch")
        .arg("--ignore")
        .arg("/*")
        .arg("--ignore")
        .arg("x/*")
        .arg("--ignore")
        .arg("testsuite/*")
        .arg("--ignore-not-existing")
        .arg("-o")
        //TODO: Paths seem to be a thing
        .arg(lcov_file_path);
    info!("Converting lcov.info file to html");
    info!("{:?}", lcov_file);
    lcov_file.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    if let Some(err) = lcov_file.output().err() {
        Err(Error::new(err).context("Failed to generate lcov.info with grcov"))
    } else {
        Ok(())
    }
}

fn exec_grcov(html_cov_path: &Path) -> Result<()> {
    let debug_dir = project_root().join("target/debug/");
    let mut grcov_html = Command::new("grcov");
    //grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing --ignore "/*" -o $HOME/output/
    grcov_html
        .current_dir(project_root())
        //output file from coverage: gcda files
        .arg(project_root().as_os_str())
        .arg("--binary-path")
        .arg(debug_dir.as_os_str())
        //source code location
        .arg("-s")
        .arg(project_root().as_os_str())
        //html output
        .arg("-t")
        .arg("html")
        //        .arg("--llvm")
        .arg("--branch")
        .arg("--ignore")
        .arg("/*")
        .arg("--ignore")
        .arg("x/*")
        .arg("--ignore")
        .arg("testsuite/*")
        .arg("--ignore-not-existing")
        .arg("-o")
        .arg(html_cov_path);
    info!("Build grcov Html Coverage Report");
    info!("{:?}", grcov_html);
    grcov_html.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    if let Some(err) = grcov_html.output().err() {
        Err(Error::new(err).context("Failed to generate html output with grcov"))
    } else {
        Ok(())
    }
}
