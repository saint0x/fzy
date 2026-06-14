#[path = "core/defs.rs"]
mod defs;
#[path = "core/env.rs"]
mod env;
#[path = "core/io.rs"]
mod io;
#[path = "core/rt.rs"]
mod rt;

pub(super) fn runtime_shim_section_core() -> String {
    let mut out = String::new();
    out.push_str(&self::defs::section());
    out.push_str(&self::env::section());
    out.push_str(&self::io::section());
    out.push_str(&self::rt::section());
    out
}
