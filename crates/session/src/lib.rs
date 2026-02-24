#[derive(Debug, Clone, Copy)]
pub enum Profile {
    Dev,
    Release,
    Verify,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub profile: Profile,
    pub deterministic: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            profile: Profile::Dev,
            deterministic: false,
        }
    }
}
