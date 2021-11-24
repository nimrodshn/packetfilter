use anyhow::Result;
use aya::maps::{HashMap, MapRefMut};
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use std::convert::TryFrom;
use std::{
    convert::TryInto,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    thread,
    time::Duration,
};
use tokio::task;

const IFACE: &str = "eth0";
const DEFAULT_KEY: u32 = 0;
const BPF_NONEXIST: u64 = 2;

pub struct Code {
    bpf: Bpf,
}

impl Code {
    pub fn new(bytecode: &[u8]) -> Result<Self> {
        let bpf = Bpf::load(bytecode)?;
        Ok(Self { bpf })
    }

    pub fn exec(&mut self) -> Result<()> {
        let program_names = self
            .bpf
            .programs()
            .map(|p| p.name().to_owned())
            .collect::<Vec<_>>();

        for name in program_names {
            let probe: &mut Xdp = self.bpf.program_mut(&name)?.try_into()?;
            probe.load()?;
            probe.attach(IFACE, XdpFlags::default())?;
        }

        let events: HashMap<MapRefMut, u32, u32> = HashMap::try_from(self.bpf.map_mut("events")?)?;
        task::spawn(async move {
            loop {
                unsafe {
                    if let Ok(ip_addr) = events.get(&DEFAULT_KEY, BPF_NONEXIST) {
                        println!("Recieved packet from {}!", ip_addr);
                    }
                }
            }
        });

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        // Create a Ctrl-C event listener.
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");

        // Loop waiting for Ctrl-C
        println!("Waiting for Ctrl-C...");
        while running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(500))
        }
        println!("Exiting...");

        Ok(())
    }
}
