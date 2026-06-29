#[path = "fs/bytes.rs"]
mod bytes;
#[path = "fs/file.rs"]
mod file;
#[path = "fs/path.rs"]
mod path;
#[path = "fs/store.rs"]
mod store;
#[path = "fs/time.rs"]
mod time;

pub(super) fn section() -> String {
    let mut out = String::new();
    out.push_str(self::time::section());
    out.push_str(self::bytes::section());
    out.push_str(self::file::section());
    out.push_str(self::store::section());
    out.push_str(self::path::section());
    out
}
