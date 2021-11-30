use anyhow::{anyhow, Result};
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

const ETHER_TYPE_IPV4_BE: [u8; 2] = [0x08, 0x00];
const ETHER_TYPE_IPV6_BE: [u8; 2] = [0x86, 0xDD];

#[derive(Debug, FromBytes, AsBytes, Default)]
#[repr(C)]
pub struct EthernetHeader {
    pub dest: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: [u8; 2],
}

/// An in-memory representation of a packet recieved.
/// Packets can be either IPv4 or IPv6 not other protocols are supported.
pub struct Packet<'a> {
    pub ether_header: LayoutVerified<&'a [u8], EthernetHeader>,
    pub ip_header: Layer3Hdr<&'a [u8]>,
}

pub enum Layer3Hdr<B> {
    IPv4(LayoutVerified<B, Ipv4Header>),
    IPv6(LayoutVerified<B, Ipv6Header>),
}

#[derive(FromBytes, AsBytes, Debug, Unaligned)]
#[repr(C)]
pub struct Ipv4Header {
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

#[derive(FromBytes, AsBytes, Debug, Unaligned)]
#[repr(C)]
pub struct Ipv6Header {
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

impl<'a> Packet<'a> {
    pub fn new(frame: &'a [u8]) -> Result<Packet<'a>> {
        let (ether_header, datagram) = LayoutVerified::<_, EthernetHeader>::new_from_prefix(frame)
            .ok_or_else(|| anyhow!("Failed to serialize Ethernet header."))?;
   
        let ip_header = match ether_header.ether_type {
            ETHER_TYPE_IPV4_BE => {
                let (ip_header, _) =
                    LayoutVerified::<_, Ipv4Header>::new_unaligned_from_prefix(datagram)
                        .ok_or_else(|| anyhow!("Failed to serialize layer three header on an IPv4 packet."))?;
                Layer3Hdr::IPv4(ip_header)
            }
            ETHER_TYPE_IPV6_BE => {
                let (ip_header, _) =
                    LayoutVerified::<_, Ipv6Header>::new_unaligned_from_prefix(datagram)
                        .ok_or_else(|| anyhow!("Failed to serialize layer three header on an IPv6 packet."))?;
                Layer3Hdr::IPv6(ip_header)
            }
            _ => {
                return Err(anyhow!(
                    "Unkown EtherType {:?}, The following protocols are supported: IPv4, IPv6",
                    ether_header.ether_type
                ))
            }
        };
        Ok(Packet {
            ether_header,
            ip_header,
        })
    }
}
