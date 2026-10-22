// `deny`, not `forbid`: `raw.rs` alone allows the one call cryptoki cannot make safely (ADR-0013).
#![deny(unsafe_code)]
//! A Nacre [`Signer`](nacre_core::Signer) whose private key never leaves a PKCS#11 token: an
//! HSM, a smart card, a YubiKey PIV slot or SoftHSM.
//!
//! [`Pkcs11Signer::open`] loads a module, logs in with a [`Pin`], finds the private key by
//! label or id and its certificate by the key's id, and signs digests in ECDSA P-256 (the
//! token's raw `r||s` returned as DER) or RSA PKCS#1 v1.5 with SHA-256. Keys that ask for
//! the PIN at every signature (`CKA_ALWAYS_AUTHENTICATE`, such as PIV slot 9c) are
//! supported.
//!
//! The PIN lives only in a [`Pin`], which zeroizes its buffer on drop and implements neither
//! `Clone`, `Debug` nor `Display`. `open` drops it before returning, unless the key asks for
//! the PIN at every signature: the signer then keeps it until the signer itself is dropped or
//! the token refuses it.
//! No error of this crate shows the PIN, a label or the module path, and a refused PIN is
//! never sent to the token again: a signer whose PIN the token refuses at a signature
//! forgets it and fails every later signature.
//!
//! PKCS#11 login state belongs to the application and the token, not to a session: a token
//! this process is already logged in to would not check the PIN, so `open` refuses it and
//! there is one signer per module and token in a process. A signer whose signature failed may leave
//! an operation pending on its session: drop it and open a new one.

mod convert;
mod error;
mod pin;
mod raw;
mod signer;

pub use error::{Error, PinState};
pub use pin::Pin;
pub use signer::{Config, KeySelector, Pkcs11Signer};
