use std::fmt;

/// The error every function of this crate returns.
///
/// No message names the module path, a token or key label, nor the PIN.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The PKCS#11 module could not be loaded or exposes no usable function list.
    // No source: a loading error names the file it failed to open (ADR-0012).
    #[error("the PKCS#11 module cannot be loaded")]
    ModuleUnavailable,
    /// A PKCS#11 call failed; the source is the module's answer.
    #[error("a PKCS#11 call failed")]
    Pkcs11(#[source] cryptoki::error::Error),
    /// No slot holds an initialized token.
    #[error("no PKCS#11 token is present")]
    NoToken,
    /// No token carries the label asked for.
    #[error("no PKCS#11 token carries the label asked for")]
    TokenNotFound,
    /// Several tokens are present and none was named.
    #[error("several PKCS#11 tokens are present; name one by its label")]
    SeveralTokens,
    /// The token refused the PIN, or has locked it; the state is what the token reports.
    #[error("the token refused the PIN ({0})")]
    WrongPin(PinState),
    /// The token refused this signer's PIN at an earlier signature; the signer dropped it.
    #[error("the token refused this signer's PIN earlier; open a new signer")]
    PinRefused,
    /// This process is already logged in to the token, so the PIN would go unchecked.
    #[error("this process is already logged in to the token; open one signer per token")]
    AlreadyLoggedIn,
    /// No private key matches the selector.
    #[error("no private key matches the selector")]
    KeyNotFound,
    /// Several private keys match the selector.
    #[error("several private keys match the selector")]
    SeveralKeys,
    /// No certificate on the token carries the key's id.
    #[error("no certificate on the token carries the key's id")]
    CertificateNotFound,
    /// The key is neither an ECDSA P-256 key nor an RSA key.
    #[error("the key is neither ECDSA P-256 nor RSA")]
    UnsupportedKey,
    /// The token returned an ECDSA signature that is not a valid 64-byte `r||s`.
    #[error("the token returned a {actual}-byte ECDSA signature, not a valid 64-byte r||s")]
    SignatureLength { actual: usize },
}

impl Error {
    /// The coarse category of this error, safe to show to an untrusted party.
    pub fn kind(&self) -> nacre_core::ErrorKind {
        use nacre_core::ErrorKind::Signer;
        match self {
            Self::ModuleUnavailable => Signer,
            Self::Pkcs11(_) => Signer,
            Self::NoToken => Signer,
            Self::TokenNotFound => Signer,
            Self::SeveralTokens => Signer,
            Self::WrongPin(_) => Signer,
            Self::PinRefused => Signer,
            Self::AlreadyLoggedIn => Signer,
            Self::KeyNotFound => Signer,
            Self::SeveralKeys => Signer,
            Self::CertificateNotFound => Signer,
            Self::UnsupportedKey => Signer,
            Self::SignatureLength { .. } => Signer,
        }
    }
}

/// What the token says about its user PIN after refusing it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinState {
    /// The token reports that few tries are left.
    CountLow,
    /// The next wrong PIN locks the token.
    FinalTry,
    /// The PIN is locked; no try is left.
    Locked,
    /// The token reports nothing about its remaining tries.
    Unreported,
}

impl fmt::Display for PinState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CountLow => "few tries left",
            Self::FinalTry => "final try left",
            Self::Locked => "PIN locked",
            Self::Unreported => "no try count reported",
        })
    }
}

/// The state from the token's flags; `locked_rv` is a `CKR_PIN_LOCKED` answer to the login.
pub(crate) fn pin_state(
    count_low: bool,
    final_try: bool,
    locked: bool,
    locked_rv: bool,
) -> PinState {
    if locked || locked_rv {
        PinState::Locked
    } else if final_try {
        PinState::FinalTry
    } else if count_low {
        PinState::CountLow
    } else {
        PinState::Unreported
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nacre_core::ErrorKind;

    #[test]
    fn every_variant_has_its_kind() {
        let rows: Vec<(Error, ErrorKind)> = vec![
            (Error::ModuleUnavailable, ErrorKind::Signer),
            (
                Error::Pkcs11(cryptoki::error::Error::NotSupported),
                ErrorKind::Signer,
            ),
            (Error::NoToken, ErrorKind::Signer),
            (Error::TokenNotFound, ErrorKind::Signer),
            (Error::SeveralTokens, ErrorKind::Signer),
            (Error::WrongPin(PinState::Locked), ErrorKind::Signer),
            (Error::PinRefused, ErrorKind::Signer),
            (Error::AlreadyLoggedIn, ErrorKind::Signer),
            (Error::KeyNotFound, ErrorKind::Signer),
            (Error::SeveralKeys, ErrorKind::Signer),
            (Error::CertificateNotFound, ErrorKind::Signer),
            (Error::UnsupportedKey, ErrorKind::Signer),
            (Error::SignatureLength { actual: 63 }, ErrorKind::Signer),
        ];
        for (error, kind) in rows {
            assert_eq!(error.kind(), kind, "{error}");
        }
    }

    #[test]
    fn pin_state_follows_the_token_flags() {
        assert_eq!(pin_state(true, true, true, false), PinState::Locked);
        assert_eq!(pin_state(true, true, false, false), PinState::FinalTry);
        assert_eq!(pin_state(true, false, false, false), PinState::CountLow);
        assert_eq!(pin_state(false, false, false, true), PinState::Locked);
        assert_eq!(pin_state(false, false, false, false), PinState::Unreported);
    }
}
