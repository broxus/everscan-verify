use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Versions {
    solc_versions: Arc<BTreeMap<String, String>>,
    linker_versions: Arc<BTreeSet<String>>,
}

impl Versions {
    pub fn new(path_to_versions: &str) -> Result<Arc<Self>> {
        let json = std::fs::read_to_string(path_to_versions)?;
        let versions: Versions = serde_json::from_str(&json)?;

        Ok(Arc::new(versions))
    }

    pub fn check_compiler_version(&self, version: &str) -> bool {
        self.solc_versions.contains_key(version)
    }

    pub fn check_linker_version(&self, version: &str) -> bool {
        self.linker_versions.contains(version)
    }

    pub fn linker_versions(&self) -> &BTreeSet<String> {
        &self.linker_versions
    }

    pub fn solc_versions(&self) -> &BTreeMap<String, String> {
        &self.solc_versions
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_works() {
        Versions::new("../versions_map.json").expect("Failed");
    }
}
