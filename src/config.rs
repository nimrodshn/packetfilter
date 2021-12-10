use anyhow::Result;
use aya::maps::lpm_trie;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{fs::read_to_string, str::FromStr};

use std::net::IpAddr;

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    network_rule_collections: Vec<NetworkRuleCollection>,
}

impl Config {
    pub fn new(path: &Path) -> Result<Config> {
        let contents = read_to_string(path)?;
        let res: Config = serde_json::from_str(&contents)?;
        Ok(res)
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct NetworkRuleCollection {
    name: String,
    priority: u32,
    rules: Vec<NetworkRule>,
}

#[derive(Deserialize, Serialize, Debug)]
enum RuleActionType {
    Deny,
    Allow,
    LogOnly,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct RuleAction {
    // 'type'j is a keyword, in order to serialize this field name the compiler requires the 'r#' prefix.
    r#type: RuleActionType,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct NetworkRule {
    actions: Vec<RuleAction>,
    destination_ips: Option<Vec<String>>,
    destination_ip_groups: Option<Vec<String>>,
    destination_fqdns: Option<Vec<String>>,
    destination_ports: Vec<String>,
    name: String,
    priority: u32,
    protocols: Vec<String>,
    source_ips: Option<Vec<String>>,
    source_ip_groups: Option<Vec<String>>,
    ip_set_hash: Option<String>,
    index: Option<u32>,
}

impl Config {
    /// as_ipv6_trie_keys converts the given configuration under network_rule_collections
    /// to aya::lpm_trie::Key struct to be used as an index for an LPMTrie map.
    pub fn as_ipv6_trie_keys(&self) -> Result<Vec<lpm_trie::Key<u128>>> {
        let mut res = vec![];
        for collection in &self.network_rule_collections {
            for rule in &collection.rules {
                if let Some(source_ips) = &rule.source_ips {
                    for ip in source_ips {
                        let prefix: u32;
                        let ip_addr: IpAddr;
                        if ip.contains("/") {
                            let (addr, mask) = ip.split_once("/").unwrap();
                            prefix = mask.parse()?;
                            ip_addr = IpAddr::from_str(addr)?;
                        } else {
                            ip_addr = IpAddr::from_str(ip)?;
                            match ip_addr {
                                IpAddr::V4(_) => prefix = 32,
                                IpAddr::V6(_) => prefix = 128,
                            };
                        }
                        match ip_addr {
                            // Drop IPv4 addresses as were interested in IPv6.
                            IpAddr::V4(_) => {}
                            IpAddr::V6(ipaddr) => {
                                // We write our addresses in BigEndian as network order is always big endian
                                // regardles of the machine.
                                res.push(lpm_trie::Key::new(prefix, u128::from(ipaddr).to_be()));
                            }
                        }
                    }
                }
            }
        }
        Ok(res)
    }
}
