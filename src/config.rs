use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use std::path::Path;

#[derive(Deserialize, Serialize)]
struct Config {
    network_rule_collections: Vec<NetworkRuleCollection>,
}

impl Config {
    fn new(path: &Path) -> Result<Config> {
        let contents = read_to_string(path)?;
        let res: Config = serde_json::from_str(&contents)?;
        Ok(res)
    }
}

#[derive(Deserialize, Serialize)]
struct NetworkRuleCollection {
    name: String,
    priority: u32,
    rules: Vec<NetworkRule>,
}

#[derive(Deserialize, Serialize)]
enum RuleActions {
    Deny,
    Allow,
    LogOnly
}

#[derive(Deserialize, Serialize)]
struct NetworkRule {
    actions: RuleActions,
    destinationips: Vec<String>,
    destinationipgroups: Vec<String>,
    destinationfqdns: Vec<String>,
    destinationports: Vec<String>,
    name: String,
    priority: u32,
    protocols: Vec<String>,
    sourceips: Vec<String>,
    sourceipgroups: Vec<String>,
    ipsethash: String,
    index: u32,
}
