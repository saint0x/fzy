use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub package: Package,
    #[serde(default)]
    pub target: Target,
    #[serde(default)]
    pub deps: BTreeMap<String, Dependency>,
    #[serde(default)]
    pub profiles: Profiles,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Target {
    #[serde(default)]
    pub bin: Vec<BinTarget>,
    pub lib: Option<LibTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinTarget {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibTarget {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Dependency {
    Path { path: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profiles {
    pub dev: Option<Profile>,
    pub release: Option<Profile>,
    pub verify: Option<Profile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profile {
    pub optimize: Option<bool>,
    pub checks: Option<bool>,
}

impl Manifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.package.name.trim().is_empty() {
            return Err("package.name cannot be empty".to_string());
        }
        if self.package.version.trim().is_empty() {
            return Err("package.version cannot be empty".to_string());
        }
        if self.target.bin.is_empty() && self.target.lib.is_none() {
            return Err("manifest must define at least one target".to_string());
        }
        Ok(())
    }

    pub fn primary_bin_path(&self) -> Option<&str> {
        self.target.bin.first().map(|bin| bin.path.as_str())
    }
}

pub fn load(contents: &str) -> Result<Manifest, toml::de::Error> {
    toml::from_str(contents)
}

#[cfg(test)]
mod tests {
    use super::load;

    #[test]
    fn loads_manifest() {
        let input = r#"
            [package]
            name = "demo"
            version = "0.1.0"

            [[target.bin]]
            name = "demo"
            path = "src/main.fzy"
        "#;
        let manifest = load(input).expect("manifest should parse");
        assert_eq!(manifest.package.name, "demo");
        manifest
            .validate()
            .expect("manifest should pass validation");
        assert_eq!(manifest.primary_bin_path(), Some("src/main.fzy"));
    }
}
