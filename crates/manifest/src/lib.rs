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
    Path {
        path: String,
    },
    Version {
        version: String,
        #[serde(default)]
        source: Option<String>,
    },
    Git {
        git: String,
        rev: String,
    },
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
        for (name, dep) in &self.deps {
            match dep {
                Dependency::Path { path } => {
                    if path.trim().is_empty() {
                        return Err(format!("deps.{name}.path cannot be empty"));
                    }
                }
                Dependency::Version { version, source } => {
                    if version.trim().is_empty() {
                        return Err(format!("deps.{name}.version cannot be empty"));
                    }
                    if let Some(source) = source {
                        if source.trim().is_empty() {
                            return Err(format!("deps.{name}.source cannot be empty when set"));
                        }
                    }
                }
                Dependency::Git { git, rev } => {
                    if git.trim().is_empty() {
                        return Err(format!("deps.{name}.git cannot be empty"));
                    }
                    if rev.trim().is_empty() {
                        return Err(format!("deps.{name}.rev cannot be empty"));
                    }
                }
            }
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

    #[test]
    fn loads_remote_dependency_variants() {
        let input = r#"
            [package]
            name = "demo"
            version = "0.1.0"

            [[target.bin]]
            name = "demo"
            path = "src/main.fzy"

            [deps]
            stable={version="1.2.3",source="registry+https://registry.example.test"}
            parser={git="https://github.com/example/parser.git",rev="abc123"}
        "#;
        let manifest = load(input).expect("manifest should parse");
        manifest
            .validate()
            .expect("manifest should pass validation");
        assert!(matches!(
            manifest.deps.get("stable"),
            Some(super::Dependency::Version { .. })
        ));
        assert!(matches!(
            manifest.deps.get("parser"),
            Some(super::Dependency::Git { .. })
        ));
    }
}
