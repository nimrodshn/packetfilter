use anyhow::Result;
use aya::programs::{Xdp, XdpFlags};
use aya::{Bpf};
use std::{
    convert::TryInto,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration
};
use log::debug;

const IFACE: &str = "eth0";

pub struct Code {
    bpf: Bpf,
}

impl Code {
    pub fn new(bytecode: &[u8]) -> Result<Self> {
        let bpf = Bpf::load(bytecode)?;
        Ok(Self { bpf })
    }

    pub fn exec(&mut self) -> Result<()> {

        let program_names = self.bpf.programs().map(|p| {
            p.name().to_owned()
        }).collect::<Vec<_>>();

        for name in program_names {          
            let probe: &mut Xdp = self.bpf.program_mut(&name)?.try_into()?;
            probe.load()?;
            debug!("loaded {}", name);

            probe.attach(IFACE, XdpFlags::default())?;
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
    
        // Create a Ctrl-C event listener.
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");
    
        // Loop waiting for Ctrl-C
        println!("Waiting for Ctrl-C...");
        while running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(500))
        }
        println!("Exiting...");

        Ok(())
    }
}
