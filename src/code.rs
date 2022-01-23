use crate::config::Config;
use crate::packet::{Layer3Hdr, Packet};
use anyhow::{anyhow, Result};
use aya::{
    maps::{lpm_trie::LpmTrie, perf::AsyncPerfEventArray},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use std::{
    convert::{TryFrom, TryInto},
    net::{Ipv4Addr, Ipv6Addr},
};
use tokio::{signal, task};

const IFACE: &str = "lo";

pub struct Code {
    bpf: Bpf,
    config: Config,
}

impl Code {
    pub fn new(bytecode: &[u8], config: Config) -> Result<Self> {
        let bpf = Bpf::load(bytecode)?;
        Ok(Self { bpf, config })
    }

    pub async fn exec(&mut self) -> Result<()> {
        let program_names = self
            .bpf
            .programs()
            .map(|(name, _)| name.to_owned())
            .collect::<Vec<_>>();

        for name in program_names {
            let probe: &mut Xdp = self
                .bpf
                .program_mut(&name)
                .ok_or(anyhow!("Failed to find a BPF program with name: {}", name))?
                .try_into()?;
            probe.load()?;
            probe.attach(IFACE, XdpFlags::default())?;
        }

        let source_ip_blacklist = self.bpf.map_mut("source_ip_blacklist")?;
        let source_ip_trie = LpmTrie::try_from(source_ip_blacklist)?;

        let source_ip_keys = self.config.as_ipv6_trie_keys()?;
        for key in source_ip_keys.into_iter() {
            source_ip_trie.insert(&key, 1 as u32, 0)?;
        }

        let events = self.bpf.map_mut("events")?;
        let mut events = AsyncPerfEventArray::try_from(events)?;

        for cpu in online_cpus()? {
            let mut buf = events.open(cpu, None)?;
            let mut bufs = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            task::spawn(async move {
                loop {
                    let events = buf.read_events(&mut bufs).await.unwrap();
                    for i in 0..events.read {
                        let buf = bufs[i].to_owned();
                        let packet = Packet::new(&buf).unwrap();
                        match packet.ip_header {
                            Layer3Hdr::IPv4(ipv4) => {
                                println!(
                                    "IPV4 PACKET LOG: SOURCE: {},  DESTINATION: {}",
                                    Ipv4Addr::from(ipv4.src),
                                    Ipv4Addr::from(ipv4.dst),
                                )
                            }
                            Layer3Hdr::IPv6(ipv6) => {
                                println!(
                                    "IPV6 PACKET LOG: SOURCE: {},  DESTINATION: {}",
                                    Ipv6Addr::from(ipv6.src),
                                    Ipv6Addr::from(ipv6.dst),
                                )
                            }
                        };
                    }
                }
            });
        }

        wait_until_terminated().await
    }
}

async fn wait_until_terminated() -> Result<(), anyhow::Error> {
    signal::ctrl_c().await?;
    println!("Exiting...");
    Ok(())
}
