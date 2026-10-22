use base64ct::{Base64, Encoding};
use nacre_core::{
    Indication, SignatureForm, SignatureLevel, SignatureProfile, SubIndication, ValidationReport,
};
use serde_json::Value;

use crate::Error;

/// DSS's verdict on one signature of the submitted file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureVerdict {
    /// DSS's identifier of the signature (`S-…`).
    pub id: String,
    /// `SignatureFormat` exactly as DSS wrote it, such as `PAdES-BASELINE-B` or `PDF-NOT-ETSI`.
    pub format: String,
    /// Indication, sub-indication and the level read from `format`.
    pub report: ValidationReport,
}

/// What DSS answered for one submitted file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reports {
    /// The signatures of the simple report, in report order; timestamps and evidence records
    /// listed beside them are skipped.
    pub signatures: Vec<SignatureVerdict>,
    /// The ETSI EN 319 102-1 `ValidationReport`, as the XML DSS produced.
    pub etsi_xml: String,
}

/// Reads the JSON answer of DSS 6.5.1's `validateSignature`.
///
/// The level comes from each signature's `SignatureFormat`; DSS's `SignatureLevel` is the
/// qualification (`N/A` on the bench) and is not read.
pub fn parse_response(body: &[u8]) -> Result<Reports, Error> {
    let response: Value = serde_json::from_slice(body)?;
    let simple = response
        .get("SimpleReport")
        .ok_or(Error::Report("no SimpleReport"))?;
    let items: &[Value] = match simple.get("signatureOrTimestampOrEvidenceRecord") {
        None | Some(Value::Null) => &[],
        Some(Value::Array(items)) => items,
        Some(_) => {
            return Err(Error::Report(
                "signatureOrTimestampOrEvidenceRecord is not an array",
            ));
        }
    };
    let signatures = items
        .iter()
        .filter_map(|item| item.get("Signature"))
        .map(signature_verdict)
        .collect::<Result<Vec<_>, _>>()?;

    let encoded = response
        .get("validationReportDataHandler")
        .and_then(Value::as_str)
        .ok_or(Error::Report("no validationReportDataHandler"))?;
    let xml = Base64::decode_vec(encoded)
        .map_err(|_| Error::Report("validationReportDataHandler is not base64"))?;
    let etsi_xml =
        String::from_utf8(xml).map_err(|_| Error::Report("the ETSI report is not UTF-8"))?;

    Ok(Reports {
        signatures,
        etsi_xml,
    })
}

fn string_field(signature: &Value, key: &'static str) -> Result<String, Error> {
    signature
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::Report(key))
}

fn signature_verdict(signature: &Value) -> Result<SignatureVerdict, Error> {
    let id = string_field(signature, "Id")?;
    let format = string_field(signature, "SignatureFormat")?;
    let indication = indication(&string_field(signature, "Indication")?)?;
    let sub_indication = match signature.get("SubIndication") {
        None | Some(Value::Null) => None,
        Some(Value::String(name)) => Some(sub_indication(name)?),
        Some(_) => return Err(Error::Report("SubIndication is not a string")),
    };
    let level = level(&format);
    let report = match (indication, sub_indication) {
        (Indication::TotalPassed, None) => ValidationReport::passed(level),
        (Indication::TotalPassed, Some(_)) => {
            return Err(Error::Report("TOTAL_PASSED with a sub-indication"));
        }
        (Indication::TotalFailed, Some(sub)) => ValidationReport::failed(sub, level),
        (Indication::Indeterminate, Some(sub)) => ValidationReport::indeterminate(sub, level),
        _ => {
            return Err(Error::Report(
                "a failed indication without a sub-indication",
            ));
        }
    };
    Ok(SignatureVerdict { id, format, report })
}

fn indication(name: &str) -> Result<Indication, Error> {
    [
        Indication::TotalPassed,
        Indication::TotalFailed,
        Indication::Indeterminate,
    ]
    .into_iter()
    .find(|indication| indication.as_str() == name)
    .ok_or(Error::Report("unknown Indication"))
}

fn sub_indication(name: &str) -> Result<SubIndication, Error> {
    SubIndication::ALL
        .into_iter()
        .find(|sub| sub.as_str() == name)
        .ok_or(Error::Report("unknown SubIndication"))
}

/// The level a DSS 6.5.1 `SignatureFormat` names, such as `PAdES-BASELINE-B` or `CAdES-BES`.
///
/// `None` for a format that is not an AdES level (`PDF-NOT-ETSI`, `UNKNOWN`) or that Nacre has
/// no form for (`CB-AdES-…`); the raw name stays in [`SignatureVerdict::format`].
pub fn level(format: &str) -> Option<SignatureLevel> {
    let (form, rest) = format.split_once('-')?;
    let form = match form {
        "CAdES" => SignatureForm::CAdES,
        "PAdES" => SignatureForm::PAdES,
        "XAdES" => SignatureForm::XAdES,
        "JAdES" => SignatureForm::JAdES,
        "PKCS7" => SignatureForm::Pkcs7,
        _ => return None,
    };
    let profile = match (form, rest) {
        (SignatureForm::Pkcs7, "B") => SignatureProfile::BaselineB,
        (SignatureForm::Pkcs7, "T") => SignatureProfile::BaselineT,
        (SignatureForm::Pkcs7, "LT") => SignatureProfile::BaselineLt,
        (SignatureForm::Pkcs7, "LTA") => SignatureProfile::BaselineLta,
        (SignatureForm::Pkcs7, _) => return None,
        (_, "BASELINE-B") => SignatureProfile::BaselineB,
        (_, "BASELINE-T") => SignatureProfile::BaselineT,
        (_, "BASELINE-LT") => SignatureProfile::BaselineLt,
        (_, "BASELINE-LTA") => SignatureProfile::BaselineLta,
        (SignatureForm::JAdES, _) => return None,
        (_, "BES") => SignatureProfile::ExtendedBes,
        (_, "EPES") => SignatureProfile::ExtendedEpes,
        (SignatureForm::PAdES, "LTV") => SignatureProfile::ExtendedLtv,
        (SignatureForm::PAdES, _) => return None,
        (_, "T") => SignatureProfile::ExtendedT,
        (_, "LT") => SignatureProfile::ExtendedLt,
        (_, "C") => SignatureProfile::ExtendedC,
        (_, "X") => SignatureProfile::ExtendedX,
        (_, "XL") => SignatureProfile::ExtendedXl,
        (_, "A") => SignatureProfile::ExtendedA,
        (_, "ERS") => SignatureProfile::ExtendedErs,
        _ => return None,
    };
    Some(SignatureLevel { form, profile })
}
