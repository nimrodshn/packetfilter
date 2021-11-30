use crate::packet::{Layer3Hdr, Packet};
use anyhow::Result;
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net;
use tokio::{signal, task};

const IFACE: &str = "eth0";

pub struct Code {
    bpf: Bpf,
}

impl Code {
    pub fn new(bytecode: &[u8]) -> Result<Self> {
        let bpf = Bpf::load(bytecode)?;
        Ok(Self { bpf })
    }

    pub async fn exec(&mut self) -> Result<()> {
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
                                    "IPV4 PACKET LOG: SOURC: {},  DESTINATION: {}",
                                    net::Ipv4Addr::from(ipv4.src),
                                    net::Ipv4Addr::from(ipv4.dst),
                                )
                            }
                            Layer3Hdr::IPv6(ipv6) => {
                                println!(
                                    "IPV6 PACKET LOG: SOURC: {},  DESTINATION: {}",
                                    net::Ipv6Addr::from(ipv6.src),
                                    net::Ipv6Addr::from(ipv6.dst),
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
