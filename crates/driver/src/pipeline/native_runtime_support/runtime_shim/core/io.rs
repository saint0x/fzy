#[path = "io/body.rs"]
mod body;
#[path = "io/http.rs"]
mod http;
#[path = "io/json.rs"]
mod json;
#[path = "io/proc.rs"]
mod proc;
#[path = "io/sys.rs"]
mod sys;

pub(super) fn section() -> String {
    let mut out = String::new();
    out.push_str(self::sys::section());
    out.push_str(self::json::section());
    out.push_str(self::http::section());
    out.push_str(self::body::section());
    out.push_str(self::proc::section());
    out
}
