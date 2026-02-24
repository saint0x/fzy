#[path = "../entry.rs"]
mod entry;

fn main() -> anyhow::Result<()> {
    entry::run()
}
