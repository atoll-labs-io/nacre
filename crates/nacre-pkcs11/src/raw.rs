// cryptoki 0.12.1 has no single-part sign after `sign_init` (ADR-0013); replace this file with
// `Session::sign_single` once a cryptoki release carries it.
#![allow(unsafe_code)]

use std::path::Path;
use std::ptr;

use cryptoki::context::Function;
use cryptoki::error::Rv;
use cryptoki_sys::{CK_FUNCTION_LIST, CK_RV, CK_SESSION_HANDLE, CK_ULONG, CKR_OK};

use crate::Error;

type SignFn =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut u8, CK_ULONG, *mut u8, *mut CK_ULONG) -> CK_RV;

/// The module's own `C_Sign`, for a session whose operation cryptoki already started.
pub(crate) struct Module {
    // Keeps the library mapped while `sign` points into it.
    _lib: cryptoki_sys::Pkcs11,
    sign: SignFn,
}

impl Module {
    pub(crate) fn load(path: &Path) -> Result<Self, Error> {
        // SAFETY: the same path the cryptoki context loaded, so the dynamic loader returns
        // the instance already loaded and initialized; no new initializer runs.
        let lib =
            unsafe { cryptoki_sys::Pkcs11::new(path) }.map_err(|_| Error::ModuleUnavailable)?;
        let get_function_list = *lib
            .C_GetFunctionList
            .as_ref()
            .map_err(|_| Error::ModuleUnavailable)?;
        let mut list: *mut CK_FUNCTION_LIST = ptr::null_mut();
        // SAFETY: `C_GetFunctionList` only writes one pointer through its argument.
        let rv = unsafe { get_function_list(&mut list) };
        if rv != CKR_OK {
            return Err(Error::ModuleUnavailable);
        }
        // SAFETY: a non-null list points to the module's static function table, which stays
        // valid while `_lib` keeps the library mapped.
        let list = unsafe { list.as_ref() }.ok_or(Error::ModuleUnavailable)?;
        let sign = list.C_Sign.ok_or(Error::ModuleUnavailable)?;
        Ok(Self { _lib: lib, sign })
    }

    /// `C_Sign` on `session`, whose signing operation is already initialized.
    pub(crate) fn sign(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<Vec<u8>, cryptoki::error::Error> {
        let data_len: CK_ULONG = data.len().try_into()?;
        let mut signature_len: CK_ULONG = 0;
        // SAFETY: the session handle comes from a live cryptoki `Session` of the same module;
        // `data` is read only, and a null output asks only for the length.
        let rv = unsafe {
            (self.sign)(
                session,
                data.as_ptr().cast_mut(),
                data_len,
                ptr::null_mut(),
                &mut signature_len,
            )
        };
        Rv::from(rv).into_result(Function::Sign)?;

        let mut signature = vec![0u8; signature_len.try_into()?];
        // SAFETY: as above, with an output buffer of the length the module itself asked for.
        let rv = unsafe {
            (self.sign)(
                session,
                data.as_ptr().cast_mut(),
                data_len,
                signature.as_mut_ptr(),
                &mut signature_len,
            )
        };
        Rv::from(rv).into_result(Function::Sign)?;
        signature.truncate(signature_len.try_into()?);
        Ok(signature)
    }
}
