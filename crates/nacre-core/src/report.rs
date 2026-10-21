//! The outcome of a validation, named after ETSI EN 319 102-1 with the spelling of
//! DSS 6.5.1, the conformance judge.

/// The main indication of a validation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Indication {
    TotalPassed,
    TotalFailed,
    Indeterminate,
}

impl Indication {
    /// The name, as DSS spells it (`TOTAL_PASSED`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TotalPassed => "TOTAL_PASSED",
            Self::TotalFailed => "TOTAL_FAILED",
            Self::Indeterminate => "INDETERMINATE",
        }
    }

    /// The EN 319 102-1 URN (`urn:etsi:019102:mainindication:total-passed`).
    pub fn urn(self) -> &'static str {
        match self {
            Self::TotalPassed => "urn:etsi:019102:mainindication:total-passed",
            Self::TotalFailed => "urn:etsi:019102:mainindication:total-failed",
            Self::Indeterminate => "urn:etsi:019102:mainindication:indeterminate",
        }
    }
}

macro_rules! sub_indications {
    ($($variant:ident => $name:literal,)+) => {
        /// The sub-indication that qualifies a `TOTAL_FAILED` or `INDETERMINATE` result.
        #[non_exhaustive]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum SubIndication {
            $($variant,)+
        }

        impl SubIndication {
            /// Every sub-indication of EN 319 102-1, in DSS 6.5.1 order.
            pub const ALL: [SubIndication; 25] = [$(Self::$variant,)+];

            /// The name, as EN 319 102-1 and DSS spell it (`FORMAT_FAILURE`).
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }

            /// The EN 319 102-1 URN (`urn:etsi:019102:subindication:FORMAT_FAILURE`).
            pub fn urn(self) -> &'static str {
                match self {
                    $(Self::$variant => concat!("urn:etsi:019102:subindication:", $name),)+
                }
            }
        }
    };
}

sub_indications! {
    FormatFailure => "FORMAT_FAILURE",
    HashFailure => "HASH_FAILURE",
    SigCryptoFailure => "SIG_CRYPTO_FAILURE",
    Revoked => "REVOKED",
    Expired => "EXPIRED",
    NotYetValid => "NOT_YET_VALID",
    SigConstraintsFailure => "SIG_CONSTRAINTS_FAILURE",
    ChainConstraintsFailure => "CHAIN_CONSTRAINTS_FAILURE",
    CertificateChainGeneralFailure => "CERTIFICATE_CHAIN_GENERAL_FAILURE",
    CryptoConstraintsFailure => "CRYPTO_CONSTRAINTS_FAILURE",
    PolicyProcessingError => "POLICY_PROCESSING_ERROR",
    SignaturePolicyNotAvailable => "SIGNATURE_POLICY_NOT_AVAILABLE",
    TimestampOrderFailure => "TIMESTAMP_ORDER_FAILURE",
    NoSigningCertificateFound => "NO_SIGNING_CERTIFICATE_FOUND",
    NoCertificateChainFound => "NO_CERTIFICATE_CHAIN_FOUND",
    NoCertificateChainFoundNoPoe => "NO_CERTIFICATE_CHAIN_FOUND_NO_POE",
    RevokedNoPoe => "REVOKED_NO_POE",
    RevokedCaNoPoe => "REVOKED_CA_NO_POE",
    OutOfBoundsNotRevoked => "OUT_OF_BOUNDS_NOT_REVOKED",
    OutOfBoundsNoPoe => "OUT_OF_BOUNDS_NO_POE",
    RevocationOutOfBoundsNoPoe => "REVOCATION_OUT_OF_BOUNDS_NO_POE",
    CryptoConstraintsFailureNoPoe => "CRYPTO_CONSTRAINTS_FAILURE_NO_POE",
    NoPoe => "NO_POE",
    TryLater => "TRY_LATER",
    SignedDataNotFound => "SIGNED_DATA_NOT_FOUND",
}

/// The signature format family of a level.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureForm {
    CAdES,
    PAdES,
    XAdES,
    JAdES,
    Pkcs7,
}

/// The profile of a level, mirroring DSS 6.5.1 `SignatureProfile`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureProfile {
    BaselineB,
    BaselineT,
    BaselineLt,
    BaselineLta,
    ExtendedBes,
    ExtendedEpes,
    ExtendedT,
    ExtendedLt,
    ExtendedC,
    ExtendedX,
    ExtendedXl,
    ExtendedA,
    ExtendedErs,
    ExtendedLtv,
    AdES,
    NotEtsi,
}

/// The level a signature reached: a form and a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureLevel {
    pub form: SignatureForm,
    pub profile: SignatureProfile,
}

/// The result of validating one signature.
///
/// A `TOTAL_PASSED` report never carries a sub-indication; a `TOTAL_FAILED` or
/// `INDETERMINATE` report always does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    indication: Indication,
    sub_indication: Option<SubIndication>,
    level: Option<SignatureLevel>,
}

impl ValidationReport {
    pub fn passed(level: Option<SignatureLevel>) -> Self {
        Self {
            indication: Indication::TotalPassed,
            sub_indication: None,
            level,
        }
    }

    pub fn failed(sub_indication: SubIndication, level: Option<SignatureLevel>) -> Self {
        Self {
            indication: Indication::TotalFailed,
            sub_indication: Some(sub_indication),
            level,
        }
    }

    pub fn indeterminate(sub_indication: SubIndication, level: Option<SignatureLevel>) -> Self {
        Self {
            indication: Indication::Indeterminate,
            sub_indication: Some(sub_indication),
            level,
        }
    }

    pub fn indication(&self) -> Indication {
        self.indication
    }

    pub fn sub_indication(&self) -> Option<SubIndication> {
        self.sub_indication
    }

    pub fn level(&self) -> Option<SignatureLevel> {
        self.level
    }
}
