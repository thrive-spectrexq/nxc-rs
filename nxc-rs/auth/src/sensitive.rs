use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// A newtype for sensitive strings like passwords and hashes.
/// It implements `Debug` to print `"<REDACTED>"` to avoid leaking secrets in logs.
#[derive(Clone, Serialize, Deserialize, Zeroize, Default)]
#[zeroize(drop)]
pub struct Sensitive(pub String);

impl fmt::Debug for Sensitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"<REDACTED>\"")
    }
}

impl std::ops::Deref for Sensitive {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Sensitive {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsRef<str> for Sensitive {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}
