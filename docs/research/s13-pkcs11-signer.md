# Research — s13-pkcs11-signer

[Story](../stories.md)

## Structuring facts
- **cryptoki 0.12.1 cannot sign with an always-authenticate key through its safe API.** A key with `CKA_ALWAYS_AUTHENTICATE` (YubiKey PIV slot 9c, the story's slot) needs `C_SignInit` → `C_Login(CKU_CONTEXT_SPECIFIC)` → `C_Sign`, but `Session::sign` runs `C_SignInit` and `C_Sign` together (`cryptoki-0.12.1/src/session/signing_macing.rs:15-57`), and CKM_ECDSA / CKM_RSA_PKCS are single-part, so `sign_update`/`sign_final` do not apply. Upstream added `Session::sign_single` (rust-cryptoki PR #357, merged 2026-02-20), but no release carries it: 0.12.1 (2026-09-16) is the latest on crates.io. ADR-0005's "unsafe stays inside cryptoki" therefore does not hold for slot 9c; the convention's exception ("only `nacre-pkcs11` may relax it, and only for a call `cryptoki` cannot make safely", `AGENTS.local.md`) is exactly this case. Spike: on SoftHSM 2.7.0, `sign_init` + context login + a raw `cryptoki_sys` `C_Sign` on the same session signs, twice in a row; plain `sign()` on that key gives `UserNotLoggedIn`.
- **SoftHSM never reports two of the three PIN states of criterion 3.** Spike, 12 wrong PINs in a row on SoftHSM 2.7.0: `CKR_PIN_INCORRECT` each time, then `CKF_USER_PIN_COUNT_LOW` set, never `CKF_USER_PIN_FINAL_TRY` nor `CKF_USER_PIN_LOCKED`; the right PIN still logs in. "Dernier essai" and "verrouillé" are provable only by a unit test of the flag mapping; the real YubiKey must not be used to provoke them (PIV retry counter).
- **The research spike on the real YubiKey cannot run here** (story notes): it needs the owner, the key plugged in and the PIN typed. It becomes the manual run of criterion 5, written by the implementer in `crates/nacre-pkcs11/MANUAL.md` and run by the person. `libykcs11.so.2.7.3` is installed at `/usr/lib/libykcs11.so`; nothing else was checked on the hardware.
- **Criterion 4 cannot mean "erased right after login" for slot 9c** (issue #9): the context login before each signature needs the PIN again, and `Signer::sign_digest` takes a digest only (`crates/nacre-core/src/signer.rs:16`). Concrete form proposed: *the PIN lives only in a type that zeroizes on drop; the signer keeps it only when the key is always-authenticate, until the signer is dropped; no `Debug`, `Display` or error message of the crate shows it.*
- **Patelle's SoftHSM tests cannot be copied as they are**: they set `SOFTHSM2_CONF` with `unsafe { std::env::set_var }` (`patelle story/s01-sign-decision:lib/tests/contract_signer.rs:28`) and shell out to `softhsm2-util` (`lib/tests/support/softhsm.rs:126`); Patelle's signer delegates signing to ades-rs (`lib/src/signer/pkcs11.rs:49-55`), so only its PIN-state logic (`:135-182`) carries over.

## Story
A `Signer` that signs with a key kept on a PKCS#11 token, so the private key never leaves the hardware.
1. Opens a session on a given module, logs in with a PIN, finds the key and its certificate by label or by id, signs a digest in ECDSA P-256 (raw `r||s` turned into DER) and RSA PKCS#1 v1.5.
2. In CI, a PDF signed with a SoftHSM key is judged `PAdES-BASELINE-B` by DSS.
3. A wrong PIN returns an error giving the state the token exposes (few tries left, last try, locked); no panic, no signature.
4. The PIN is erased from memory after use (`zeroize`) and appears in no error message or log (concrete form above).
5. A manual run on a real YubiKey (PIV slot 9c, `libykcs11`) is recorded in `crates/nacre-pkcs11/MANUAL.md` with DSS's report.
Owns `crates/nacre-pkcs11/` only. Depends on s06 (shipped, `373e6ba`).

## Current code
- No `crates/nacre-pkcs11/` yet; the workspace takes it by folder (`Cargo.toml:3`, `members = ["crates/*"]`).
- `nacre_core::Signer` (`crates/nacre-core/src/signer.rs:4-17`): `algorithm()`, `certificate_chain() -> &[Vec<u8>]` (own certificate first, never empty), `sign_digest(&self, digest) -> Result<Vec<u8>, Error>`; ECDSA returned as DER `ECDSA-Sig-Value`, RSA as raw bytes. No `Send`/`Sync` bound.
- `SignatureAlgorithm` (`crates/nacre-core/src/algorithm.rs:4`): `EcdsaP256Sha256`, `RsaPkcs1v15Sha256`, both SHA-256 (`:13`); `DigestAlgorithm::output_len` (`:31`).
- `nacre_core::Error` (`crates/nacre-core/src/error.rs:7`): `DigestLength { expected, actual }` (`:10`) → `InvalidInput`, `Signer(BoxError)` (`:13`) → `Signer`; `kind()` at `:24`. An implementation's error travels boxed and callers `downcast_ref` it (ADR-0010).
- `TestSigner::from_secret(&[u8; 32])` (`crates/nacre-core/src/test_signer.rs:31`, feature `test-signer`) gives a self-signed P-256 certificate for a known scalar; its `sign_digest` refuses a wrong digest length first (`:61-69`). Reusable to put a known key and its certificate on a SoftHSM token.
- `nacre_pades::sign(pdf, &dyn Signer, DateTime)` (`crates/nacre-pades/src/sign.rs:21`) calls the real signer once (dry run through `Sizing`, `src/reserve.rs:36-50`); RSA reserve read from the certificate's key (`reserve.rs:20`).
- s06's conformance test pattern (`crates/nacre-pades/tests/conformance.rs:25-44`, support `tests/support/mod.rs`): bench key `signer.key.pem` + chain `signer.cert.pem`, `intermediate.cert.pem` from `nacre_conformance::pki_dir()` (`crates/nacre-conformance/src/lib.rs:53`), `Dss::from_env()?.validate(name, bytes)` (`client.rs:48,60`), asserts `TotalPassed`, no sub-indication, `format == "PAdES-BASELINE-B"`.
- Every crate root holds `#![forbid(unsafe_code)]` (`crates/{nacre-core,nacre-cms,nacre-pdf,nacre-pades,nacre-conformance}/src/lib.rs`); workspace lints deny `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` (`Cargo.toml:5-9`).
- Error pattern: one `thiserror` enum, `kind()` with one arm per variant and a unit test `every_variant_has_its_kind` (`crates/nacre-pades/src/error.rs:13-50`).

## Attachment points
- New crate `crates/nacre-pkcs11/` implementing `nacre_core::Signer`.
- CI: `.github/workflows/conformance.yml` already installs `softhsm2` (`:40`) before `cargo test --workspace --all-features -- --ignored` (`:41`) and exports `NACRE_SOFTHSM_MODULE=/usr/lib/softhsm/libsofthsm2.so` (`:18`); `ci.yml` runs only `cargo test --workspace` and clippy `--all-targets --all-features` (`ci.yml:15-17`). No workflow edit needed (the stories review's finding on s13 is resolved by s02).
- s20 will re-export the crate behind feature `pkcs11` and run `examples/sign_blta.rs` against SoftHSM; nothing to do here.

## Verified interfaces
cryptoki 0.12.1 (opened in the registry, `~/.cargo/registry/src/*/cryptoki-0.12.1/src/`):
- `Pkcs11::new(path)` (`context/mod.rs:86`), `initialize(CInitializeArgs)` (`:167`); `CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)` (`context/locking.rs:26-38`). A second `initialize` in the same process returns `Pkcs11(CryptokiAlreadyInitialized, Initialize)` (spike). `Pkcs11` has no `Drop`: nothing finalizes the module behind another user's back.
- `get_slots_with_token()` (`context/slot_token_management.rs:57`), `get_token_info(slot)` (`:115`); `TokenInfo::{label, manufacturer_id, user_pin_count_low, user_pin_final_try, user_pin_locked, token_initialized}` (`slot/token_info.rs:126-264`).
- `open_ro_session(slot)` (`context/session_management.rs:70`); `Session` holds an `Arc` of the context, no lifetime, `Send` but not `Sync` (`session/mod.rs:45-52,74`), closes on drop; `Session::handle()` is public (`session/mod.rs:100`).
- `Session::login(UserType, Option<&AuthPin>)` (`session/session_management.rs:43`); `UserType::ContextSpecific` (`session/mod.rs:117`); `AuthPin = secrecy::SecretString` (`types.rs:285`), zeroized on drop by secrecy. Logging in twice: `UserAlreadyLoggedIn` (spike).
- `find_objects(&[Attribute])` (`session/object_management.rs:309`), `get_attributes` (`:525`), `create_object` (`:314`); `Attribute::{Class, Label, Id, AlwaysAuthenticate, EcParams, KeyType, Value, ...}`, `AttributeType::AlwaysAuthenticate` (`object.rs:44,476`).
- `Session::sign(&Mechanism, key, data)` (`session/signing_macing.rs:15`), `sign_init` (`:60`); `Mechanism::Ecdsa`, `Mechanism::RsaPkcs` (`mechanism/mod.rs:1151,1082`).
- `cryptoki::error::Rv::from(CK_RV).into_result(Function)` public (`error/rv.rs:13-20,133`); `RvError::{PinIncorrect, PinLocked, PinExpired, UserAlreadyLoggedIn, UserNotLoggedIn}` (`error/rv_error.rs:92-140`).
- `cryptoki_sys::Pkcs11::new(path)` (unsafe, libloading) and its method `C_Sign` (`cryptoki-sys-0.5.0/src/bindings/x86_64-unknown-linux-gnu.rs:6818,7475`): loading the same path again gives the same module instance, so `C_Sign` works on a session opened through cryptoki (spike).
- cryptoki logs through `log` only on unknown return values and attribute types (`error/rv.rs:122`, `object.rs:641,...`); never a PIN.

SoftHSM 2.7.0 spikes (local `/usr/lib/softhsm/libsofthsm2.so`):
- ECDSA through `CKM_ECDSA` on a 32-byte digest returns 64 bytes `r||s`; `CKM_RSA_PKCS` on 51 bytes (DigestInfo SHA-256 + digest) on a 2048-bit key returns 256 bytes.
- A private EC key created with `create_object` (`CKA_VALUE` = scalar, `CKA_EC_PARAMS` = P-256 OID DER `06 08 2a 86 48 ce 3d 03 01 07`, `CKA_ALWAYS_AUTHENTICATE` = true) is accepted; `CKA_ALWAYS_AUTHENTICATE` cannot be set afterwards on an imported key (`AttributeReadOnly`).
- After a failed context login the sign operation stays active: the next `sign()` on that session gives `OperationActive`.
- A key imported with `--id 02` and its certificate with the same id are both found by `CKA_ID`.

YubiKey (from Patelle's research, not checked on hardware here): `libykcs11` labels the 9c key and its certificate differently but gives both `CKA_ID` 2 (`patelle story/s01-sign-decision:docs/research/s01-sign-decision.md:65`); it needs `pcscd` running.

## Traps
- **Token objects are matched by `CKA_ID`, not by label**: on a YubiKey the key and certificate labels differ. Find the key by the selector, then its certificate by the key's `CKA_ID`.
- **A failed context login leaves the operation active** (spike): no automatic retry of any login, ever (each try burns a PIN try); a signer whose signature failed is to be dropped.
- **`UserAlreadyLoggedIn`**: PKCS#11 login is per application and token; a second signer in the same process gets it and the PIN is not checked again. Accepted as success, documented.
- **Error text must not carry the module path** (ADR-0012): a `libloading` error names the file it failed to open, so a load failure becomes a variant without source.
- **Tests and `SOFTHSM2_CONF`**: SoftHSM reads its configuration from the environment at `C_Initialize`; `set_var` is `unsafe` in edition 2024 and racy in the threaded test harness. Each SoftHSM test can rerun itself in a child process of the same test binary with the variable set through `Command::env`, which is safe Rust and isolates tokens and PIN counters.
- **SoftHSM tests are `#[ignore = "conformance"]`** (convention) and so run only in `conformance.yml`; `ci.yml` has no SoftHSM. The DSS test needs the bench, which is down on this machine (no `conformance/pki/out/`, port 18080 closed).
- **CI's SoftHSM is Ubuntu 24.04's 2.6.1, spikes ran on 2.7.0**: context-specific login on 2.6.1 is not verified here.
- **YubiKey slot 9c may already hold the owner's key for Patelle**: a manual step that generates a key in 9c would destroy it. MANUAL.md must offer a way that keeps an existing 9c key.
- **The YubiKey's certificate must chain to a DSS anchor**: the bench's only anchor is its root, regenerated at each bench start (`conformance/pki/README.md:17,59`).
- Issue #5 (success metric 1 at B, T, LT, LTA with the YubiKey) cannot be closed here: T, LT and LTA come from s08, s11, s12. The manual run proves B only.
- No parser in this crate (it compares EC parameter bytes and passes DER through), so no fuzz target is due.
- No migration.

## Open questions
- Does `libykcs11` 2.7.3 mark slot 9c `CKA_ALWAYS_AUTHENTICATE` and accept a context login after `C_SignInit`? The plan supports both answers; the manual run records which.
- Which PIN flags does `libykcs11` raise after a wrong PIN? Not to be tested on the owner's key; MANUAL.md records it only if the person chooses to.
- Should the signer check that the certificate's public key matches the token key? Patelle checked only the algorithm (`lib/src/signer/pkcs11.rs:188-200`); the story does not ask. The plan leaves it out.
- When will rust-cryptoki release `sign_single`? The lead may file an issue to replace the raw call then.

## Complexity
4 → 4. Third-party integration with hardware; main risk confirmed and sharpened: module divergence, plus a gap in cryptoki's released API that forces one small `unsafe` call.

## Split
Not needed (score 4).
