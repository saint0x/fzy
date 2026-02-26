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
    pub link: Link,
    #[serde(default)]
    pub deps: BTreeMap<String, Dependency>,
    #[serde(default)]
    pub profiles: Profiles,
    #[serde(default)]
    pub ffi: Ffi,
    #[serde(default, rename = "unsafe")]
    pub unsafe_policy: UnsafePolicy,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Link {
    #[serde(default)]
    pub libs: Vec<String>,
    #[serde(default)]
    pub search: Vec<String>,
    #[serde(default)]
    pub frameworks: Vec<String>,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ffi {
    pub panic_boundary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafePolicy {
    pub contracts: Option<String>,
    pub enforce_dev: Option<bool>,
    pub enforce_verify: Option<bool>,
    pub enforce_release: Option<bool>,
    #[serde(default)]
    pub deny_unsafe_in: Vec<String>,
    #[serde(default)]
    pub allow_unsafe_in: Vec<String>,
}

impl Default for UnsafePolicy {
    fn default() -> Self {
        Self {
            contracts: Some("compiler".to_string()),
            enforce_dev: Some(false),
            enforce_verify: Some(true),
            enforce_release: Some(true),
            deny_unsafe_in: Vec::new(),
            allow_unsafe_in: Vec::new(),
        }
    }
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
        for (index, lib) in self.link.libs.iter().enumerate() {
            if lib.trim().is_empty() {
                return Err(format!("link.libs[{index}] cannot be empty"));
            }
        }
        for (index, path) in self.link.search.iter().enumerate() {
            if path.trim().is_empty() {
                return Err(format!("link.search[{index}] cannot be empty"));
            }
        }
        for (index, framework) in self.link.frameworks.iter().enumerate() {
            if framework.trim().is_empty() {
                return Err(format!("link.frameworks[{index}] cannot be empty"));
            }
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
        if let Some(mode) = self.ffi.panic_boundary.as_deref() {
            if mode != "abort" && mode != "error" {
                return Err("ffi.panic_boundary must be `abort` or `error`".to_string());
            }
        }
        if let Some(mode) = self.unsafe_policy.contracts.as_deref() {
            if mode != "compiler" {
                return Err("unsafe.contracts must be `compiler`".to_string());
            }
        }
        for (index, scope) in self.unsafe_policy.deny_unsafe_in.iter().enumerate() {
            if scope.trim().is_empty() {
                return Err(format!("unsafe.deny_unsafe_in[{index}] cannot be empty"));
            }
        }
        for (index, scope) in self.unsafe_policy.allow_unsafe_in.iter().enumerate() {
            if scope.trim().is_empty() {
                return Err(format!("unsafe.allow_unsafe_in[{index}] cannot be empty"));
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

    #[test]
    fn loads_link_configuration() {
        let input = r#"
            [package]
            name = "demo"
            version = "0.1.0"

            [[target.bin]]
            name = "demo"
            path = "src/main.fzy"

            [link]
            libs = ["ssl", "crypto"]
            search = ["/usr/local/lib"]
            frameworks = ["CoreFoundation"]
        "#;
        let manifest = load(input).expect("manifest should parse");
        manifest
            .validate()
            .expect("manifest should pass validation");
        assert_eq!(manifest.link.libs.len(), 2);
        assert_eq!(manifest.link.search.len(), 1);
        assert_eq!(manifest.link.frameworks.len(), 1);
    }

    #[test]
    fn validates_ffi_panic_boundary() {
        let input = r#"
            [package]
            name = "demo"
            version = "0.1.0"

            [[target.bin]]
            name = "demo"
            path = "src/main.fzy"

            [ffi]
            panic_boundary = "error"
        "#;
        let manifest = load(input).expect("manifest should parse");
        manifest
            .validate()
            .expect("manifest should accept valid ffi panic boundary");
    }

    #[test]
    fn rejects_invalid_ffi_panic_boundary() {
        let input = r#"
            [package]
            name = "demo"
            version = "0.1.0"

            [[target.bin]]
            name = "demo"
            path = "src/main.fzy"

            [ffi]
            panic_boundary = "ignore"
        "#;
        let manifest = load(input).expect("manifest should parse");
        let err = manifest
            .validate()
            .expect_err("invalid ffi panic boundary should be rejected");
        assert!(err.contains("ffi.panic_boundary"));
    }

    #[test]
    fn validates_unsafe_scope_policy_lists() {
        let input = r#"
            [package]
            name = "demo"
            version = "0.1.0"

            [[target.bin]]
            name = "demo"
            path = "src/main.fzy"

            [unsafe]
            deny_unsafe_in = ["tests::*"]
            allow_unsafe_in = ["runtime::*"]
        "#;
        let manifest = load(input).expect("manifest should parse");
        manifest
            .validate()
            .expect("unsafe scope lists should be accepted");
        assert_eq!(manifest.unsafe_policy.deny_unsafe_in, vec!["tests::*"]);
        assert_eq!(manifest.unsafe_policy.allow_unsafe_in, vec!["runtime::*"]);
    }

    #[test]
    fn rejects_empty_unsafe_scope_entries() {
        let input = r#"
            [package]
            name = "demo"
            version = "0.1.0"

            [[target.bin]]
            name = "demo"
            path = "src/main.fzy"

            [unsafe]
            deny_unsafe_in = [""]
        "#;
        let manifest = load(input).expect("manifest should parse");
        let err = manifest
            .validate()
            .expect_err("empty unsafe scope should fail validation");
        assert!(err.contains("unsafe.deny_unsafe_in"));
    }
}
