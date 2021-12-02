use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use std::path::Path;

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
