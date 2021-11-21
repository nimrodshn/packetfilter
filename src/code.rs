use anyhow::Result;
use aya::programs::{Xdp, XdpFlags};
use aya::{Bpf};
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

        Ok(())
    }
}
