#[path = "env/boot.rs"]
mod boot;
#[path = "env/crypto.rs"]
mod crypto;

pub(super) fn section() -> String {
    let mut out = String::new();
    out.push_str(self::boot::section());
    out.push_str(self::crypto::section());
    out
}
