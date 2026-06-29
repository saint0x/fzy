#[path = "services/base.rs"]
mod base;
#[path = "services/fs.rs"]
mod fs;
#[path = "services/json.rs"]
mod json;
#[path = "services/net.rs"]
mod net;

pub(super) fn runtime_shim_section_services() -> String {
    let mut out = String::new();
    out.push_str(self::base::section());
    out.push_str(&self::fs::section());
    out.push_str(&self::net::section());
    out.push_str(self::json::section());
    out
}
