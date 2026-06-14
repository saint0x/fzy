#[path = "defs/consts.rs"]
mod consts;
#[path = "defs/strings.rs"]
mod strings;
#[path = "defs/alloc.rs"]
mod alloc;
#[path = "defs/vec.rs"]
mod vec;
#[path = "defs/store.rs"]
mod store;

pub(super) fn section() -> String {
    let mut out = String::new();
    out.push_str(self::consts::section());
    out.push_str(self::strings::section());
    out.push_str(self::alloc::section());
    out.push_str(self::vec::section());
    out.push_str(self::store::section());
    out
}
