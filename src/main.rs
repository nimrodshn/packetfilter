use anyhow::{Result,anyhow};
use clap::{App, Arg, ArgMatches, SubCommand};
use packetfilter::code::Code;
use packetfilter::config::Config;
use std::fs;
use std::path::Path;

const RUN_COMMAND: &str = "run";
const BPF_PROGRAM_FILE: &str = "bpf-program-file";
const CONFIG_FILE: &str = "config-file";

#[cfg(target_arch = "aarch64")]
const BYTECODE: &[u8] = include_bytes!("../bpf/bytecode.arm64.o");

#[cfg(target_arch = "x86_64")]
const BYTECODE: &[u8] = include_bytes!("../bpf/bytecode.x86.o");

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new("packetfilter")
        .version("0.1.0")
        .about("An eBPF based packetfilter")
        .subcommand(
            SubCommand::with_name(RUN_COMMAND)
                .about("run the packetfilter")
                .arg(
                    Arg::with_name(CONFIG_FILE)
                        .help("contains the rules used to filter and DNAT packets")
                        .long(CONFIG_FILE)
                        .value_name("CONFIG-FILE")
                        .takes_value(true)
                        .required(true)
                )
                .arg(
                    Arg::with_name(BPF_PROGRAM_FILE)
                        .help("contains the bpf program to attach the host kernel")
                        .long(BPF_PROGRAM_FILE)
                        .takes_value(true)
                        .value_name("FILE")
                        .required(false)
                )
        )
        .get_matches();

    if let Some(args) = matches.subcommand_matches(RUN_COMMAND) {
        return run_command(args).await;
    }

    Ok(())
}

async fn run_command(args: &ArgMatches<'_>) -> Result<()> {
    let bpf_program: Vec<u8> = match args.value_of(BPF_PROGRAM_FILE) {
        Some(path) => fs::read(path)?,
        None => BYTECODE.to_vec(),
    };

    let config_file_path: &Path = match args.value_of(CONFIG_FILE) {
        Some(path) => Path::new(path),
        None => return Err(anyhow!("Failed to find config-file path.")),
    };

    let config = Config::new(config_file_path)?;

    let mut code = Code::new(&bpf_program, config)?;
    code.exec().await
}
