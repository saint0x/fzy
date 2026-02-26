use core::{Capability, CapabilityToken};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    Missing(Capability),
    Parse(String),
}

pub fn require_capability(
    token: &CapabilityToken,
    required: Capability,
) -> Result<(), CapabilityError> {
    if token.allows(required) {
        Ok(())
    } else {
        Err(CapabilityError::Missing(required))
    }
}

pub fn parse_capability(name: &str) -> Result<Capability, CapabilityError> {
    Capability::parse(name).ok_or_else(|| CapabilityError::Parse(name.to_string()))
}

pub fn revoke_capability(token: &mut CapabilityToken, name: &str) -> Result<(), CapabilityError> {
    let capability = parse_capability(name)?;
    token.revoke(capability);
    Ok(())
}

pub fn delegate_capability(
    token: &CapabilityToken,
    names: &[&str],
) -> Result<CapabilityToken, CapabilityError> {
    let mut subset = Vec::new();
    for name in names {
        subset.push(parse_capability(name)?);
    }
    Ok(token.delegate_subset(subset))
}

#[cfg(test)]
mod tests {
    use core::{Capability, CapabilityToken};

    use super::{delegate_capability, require_capability, revoke_capability};

    #[test]
    fn capability_guards_and_mutations_work() {
        let mut token = CapabilityToken::new([Capability::Http, Capability::FileSystem]);
        require_capability(&token, Capability::Http).expect("token should allow http");
        revoke_capability(&mut token, "http").expect("revoke should work");
        assert!(require_capability(&token, Capability::Http).is_err());

        let delegated = delegate_capability(&token, &["fs"]).expect("delegate should work");
        require_capability(&delegated, Capability::FileSystem)
            .expect("delegated token should allow fs");
        assert!(require_capability(&delegated, Capability::Http).is_err());
    }
}
