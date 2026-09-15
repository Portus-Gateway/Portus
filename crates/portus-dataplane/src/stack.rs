//! Which network stack this process serves traffic on.

/// `PORTUS_NETWORK_STACK` (chart `dataplane.networkStack`). Pingora is the
/// release stack; anything else is an experiment compared against it on the
/// same benchmarks and conformance suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkStack {
    Pingora,
    Rama,
}

impl NetworkStack {
    pub const ENV: &str = "PORTUS_NETWORK_STACK";

    /// Parse the env value; unset or empty means Pingora.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            None | Some("") | Some("pingora") => Ok(Self::Pingora),
            Some("rama") => Ok(Self::Rama),
            Some(other) => Err(format!("{}={other:?} is not a network stack (pingora, rama)", Self::ENV)),
        }
    }

    pub fn from_env() -> Result<Self, String> {
        Self::parse(std::env::var(Self::ENV).ok().as_deref())
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Pingora => "pingora",
            Self::Rama => "rama",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkStack;

    #[test]
    fn unset_and_pingora_select_pingora_case_insensitively() {
        assert_eq!(NetworkStack::parse(None), Ok(NetworkStack::Pingora));
        assert_eq!(NetworkStack::parse(Some("")), Ok(NetworkStack::Pingora));
        assert_eq!(NetworkStack::parse(Some(" Pingora ")), Ok(NetworkStack::Pingora));
        assert_eq!(NetworkStack::parse(Some("RAMA")), Ok(NetworkStack::Rama));
    }

    #[test]
    fn unknown_values_are_rejected_by_name() {
        let err = NetworkStack::parse(Some("envoy")).unwrap_err();
        assert!(err.contains("PORTUS_NETWORK_STACK") && err.contains("envoy"), "{err}");
    }
}
