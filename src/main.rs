use anyhow::Result;
use clap::{App, Arg, ArgMatches, SubCommand};
use packetfilter::code::Code;
use std::fs;

const RUN_COMMAND: &str = "run";
const BPF_PROGRAM_FILE: &str = "bpf-program-file";

#[cfg(target_arch = "aarch64")]
const BYTECODE: &[u8] = include_bytes!("../bpf/bytecode.arm64.o");

#[cfg(target_arch = "x86_64")]
const BYTECODE: &[u8] = include_bytes!("../bpf/bytecode.x86.o");

fn main() {
    let matches = App::new("packetfilter")
        .version("0.1.0")
        .about("An eBPF based packetfilter")
        .subcommand(
            SubCommand::with_name(RUN_COMMAND)
                .about("run the packetfilter")
                .arg(
                    Arg::with_name(BPF_PROGRAM_FILE)
                        .help("contains the bpf program to attach the host kernel")
                        .long(BPF_PROGRAM_FILE)
                        .value_name("FILE")
                        .required(false)
                        .index(1),
                ),
        )
        .get_matches();

    if let Some(args) = matches.subcommand_matches(RUN_COMMAND) {
        if let Err(e) = run_command(args) {
            eprint!("Unexpected error occurred: {:#}", e)
        }
    }
}

fn run_command(args: &ArgMatches) -> Result<()> {
    let bpf_program: Vec<u8> = match args.value_of(BPF_PROGRAM_FILE) {
        Some(path) => fs::read(path)?,
        None => BYTECODE.to_vec(),
    };

    let mut code = Code::new(&bpf_program)?;
    code.exec()?;

    Ok(())
}
