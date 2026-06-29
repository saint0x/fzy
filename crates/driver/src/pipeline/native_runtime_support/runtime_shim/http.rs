#[path = "http/json.rs"]
mod json;
#[path = "http/post.rs"]
mod post;
#[path = "http/read.rs"]
mod read;
#[path = "http/stream.rs"]
mod stream;
#[path = "http/text.rs"]
mod text;

pub(super) fn runtime_shim_section_http() -> String {
    let mut out = String::new();
    out.push_str(self::text::section());
    out.push_str(self::json::section());
    out.push_str(self::stream::section());
    out.push_str(self::post::section());
    out.push_str(self::read::section());
    out
}
