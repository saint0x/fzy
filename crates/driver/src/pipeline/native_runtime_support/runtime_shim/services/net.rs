#[path = "net/bind.rs"]
mod bind;
#[path = "net/read.rs"]
mod read;
#[path = "net/meta.rs"]
mod meta;
#[path = "net/ws.rs"]
mod ws;
#[path = "net/route.rs"]
mod route;

pub(super) fn section() -> String {
    let mut out = String::new();
    out.push_str(self::bind::section());
    out.push_str(self::read::section());
    out.push_str(self::meta::section());
    out.push_str(self::ws::section());
    out.push_str(self::route::section());
    out
}
