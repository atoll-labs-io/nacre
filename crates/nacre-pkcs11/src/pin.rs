use cryptoki::types::AuthPin;
use zeroize::Zeroizing;

/// A token's user PIN.
///
/// The buffer is zeroized when the `Pin` is dropped. `Pin` implements neither `Clone`,
/// `Debug` nor `Display`, so it cannot be copied nor printed by mistake.
/// [`Pkcs11Signer::open`](crate::Pkcs11Signer::open) takes it by value and drops it before
/// returning, unless the key asks for the PIN at every signature: the signer then keeps it
/// until the signer is dropped or the token refuses it.
pub struct Pin(Zeroizing<String>);

impl Pin {
    /// Takes the caller's buffer as it is, without copying it.
    pub fn new(pin: String) -> Self {
        Self(Zeroizing::new(pin))
    }

    /// A zeroizing copy for one login.
    pub(crate) fn auth(&self) -> AuthPin {
        AuthPin::from(self.0.as_str())
    }
}

impl From<String> for Pin {
    fn from(pin: String) -> Self {
        Self::new(pin)
    }
}
