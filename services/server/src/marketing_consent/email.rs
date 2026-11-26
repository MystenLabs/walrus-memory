use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct EmailAddress(Zeroizing<String>);

impl EmailAddress {
    pub(super) fn parse(raw: &str) -> Option<Self> {
        let normalized = Zeroizing::new(raw.trim().to_lowercase());
        let (local, domain) = normalized.split_once('@')?;
        if normalized.len() > 254
            || local.is_empty()
            || domain.contains('@')
            || !domain.contains('.')
            || normalized
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return None;
        }
        Some(Self(normalized))
    }

    pub(crate) fn masked(&self) -> String {
        let (local, domain) = self.0.split_once('@').expect("validated email address");
        format!("{}***@{domain}", local.chars().next().unwrap())
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for EmailAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl fmt::Debug for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EmailAddress(<redacted>)")
    }
}
