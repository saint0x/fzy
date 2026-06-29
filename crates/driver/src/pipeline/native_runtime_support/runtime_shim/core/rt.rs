#[path = "rt/bytes.rs"]
mod bytes;
#[path = "rt/hash.rs"]
mod hash;
#[path = "rt/json.rs"]
mod json;
#[path = "rt/list.rs"]
mod list;
#[path = "rt/map.rs"]
mod map;
#[path = "rt/spawn.rs"]
mod spawn;

pub(super) fn section() -> String {
    let mut out = String::new();
    out.push_str(self::hash::section());
    out.push_str(self::bytes::section());
    out.push_str(self::spawn::section());
    out.push_str(self::json::section());
    out.push_str(self::list::section());
    out.push_str(self::map::section());
    out
}
