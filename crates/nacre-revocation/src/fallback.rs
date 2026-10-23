use nacre_core::{RevocationData, RevocationSource};

/// A [`RevocationSource`] that asks `first`, then `second` when `first` fails: OCSP then
/// CRL, for instance. When both fail, `second`'s error is returned.
#[derive(Debug, Clone)]
pub struct Fallback<A, B> {
    first: A,
    second: B,
}

impl<A, B> Fallback<A, B> {
    /// A source asking `first`, then `second`.
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A: RevocationSource, B: RevocationSource> RevocationSource for Fallback<A, B> {
    fn revocation(
        &self,
        certificate: &[u8],
        issuer: &[u8],
    ) -> Result<RevocationData, nacre_core::Error> {
        self.first
            .revocation(certificate, issuer)
            .or_else(|_| self.second.revocation(certificate, issuer))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    struct Failing;

    impl RevocationSource for Failing {
        fn revocation(&self, _: &[u8], _: &[u8]) -> Result<RevocationData, nacre_core::Error> {
            Err(nacre_core::Error::revocation("unreachable"))
        }
    }

    struct Fixed(&'static [u8]);

    impl RevocationSource for Fixed {
        fn revocation(&self, _: &[u8], _: &[u8]) -> Result<RevocationData, nacre_core::Error> {
            Ok(RevocationData::Crl(self.0.to_vec()))
        }
    }

    #[test]
    fn fallback_asks_the_second_source_when_the_first_fails() {
        let rescued = Fallback::new(Failing, Fixed(b"second"));
        assert_eq!(
            rescued.revocation(b"", b"").unwrap(),
            RevocationData::Crl(b"second".to_vec())
        );
        let kept = Fallback::new(Fixed(b"first"), Fixed(b"second"));
        assert_eq!(
            kept.revocation(b"", b"").unwrap(),
            RevocationData::Crl(b"first".to_vec())
        );
        assert!(
            Fallback::new(Failing, Failing)
                .revocation(b"", b"")
                .is_err()
        );
    }
}
