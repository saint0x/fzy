#[path = "gpu/buf.rs"]
mod buf;
#[path = "gpu/defs.rs"]
mod defs;
#[path = "gpu/launch.rs"]
mod launch;

pub(super) fn runtime_shim_section_gpu() -> String {
    let mut out = String::new();
    out.push_str(self::defs::section());
    out.push_str(self::buf::section());
    out.push_str(self::launch::section());
    out
}
