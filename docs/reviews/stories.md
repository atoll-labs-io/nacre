# Stories review — Nacre

Stories reviewed: `docs/stories.md`, against `docs/brief.md` (Entry mode: new, Platform: lib, cli), with `AGENTS.md` and `docs/decisions/0001-nacre-writes-every-signature-format.md` (accepted). The reviewer did not write these stories. Findings are rated critical, major or minor.

Review status: complete

## Coverage
| Scope item | Source section | Covered by | Covered |
| --- | --- | --- | --- |
| First milestone: features `cms`, `pades`, `tsp`, `validate`, `pkcs11` | the wedge (opening capability) | s03 (cms), s04–s06, s08, s11, s12 (pades), s07 (tsp), s14–s19 (validate), s13 (pkcs11), s20 (facade) | yes |
| Sign a PDF in PAdES B-B to B-LTA with a YubiKey over PKCS#11, an RFC 3161 timestamp and revocation data in `/DSS`, then validate it with Nacre, which returns the exact level; Patelle uses it | the wedge | s06, s08, s11, s12, s13, s18, s20 | yes (the capability is delivered; no criterion proves it with the YubiKey at all four levels, see the findings) |
| P1: the need is ATOLL LABS's, Patelle first | ## Premises | s06–s20 (Patelle-first stories), s20 notes | yes |
| P2: no Rust library gives conformant, permissively licensed PAdES baseline usable with a hardware key | ## Premises | s06, s12, s13, s20 (MIT OR Apache-2.0 in README) | yes |
| P3: formats written from scratch; primitives, ASN.1/DER and X.509 stay with RustCrypto | ## Premises | s01 notes, s03, s04, s09, s16 notes, s21–s34 | yes |
| P4: local DSS at a pinned version is the judge; each feature ships with a test of the exact level, never the indication alone | ## Premises | s02, s06, s08, s11, s12, s13, s17, s18, s21, s22, s23, s25–s27, s29, s30, s35 | yes (s23 criterion 2 breaks it, see the findings) |
| P5: validation ships in the first milestone | ## Premises | s14, s15, s16, s17, s18, s19 | yes |
| P6: each family is an independent cargo feature; `pades` alone compiles nothing from the other families | ## Premises | s20 criterion 1, s37 criterion 2 | yes |
| P7: the conformance corpus, valid and invalid, is a published deliverable maintained like the code | ## Premises | s02, s14, s15, s18, s19 | yes |
| P8: Patelle's s01 work (`Signer`, `TimestampAuthority`, SoftHSM tests, DSS container) is reused | ## Premises | s01 notes, s02 notes, s13 notes | yes |

No story falls outside the scope. s21–s37 serve the families listed after the milestone under `## Wedge & non-goals`, and P3.

## Exclusions
| Excluded item | Source section | Revived by | Revived |
| --- | --- | --- | --- |
| Rewriting primitives, ASN.1/DER or X.509 | ## Wedge & non-goals | none (s16 path validation and s10 OCSP structures are borderline, see Not verified) | no |
| Qualified signature (QES) and any certification | ## Wedge & non-goals | none (s36 loads trust lists as validation anchors only) | no |
| Being a service: server, HTTP API, TSA, CA | ## Wedge & non-goals | none (the TSA, OCSP responder and CSC server in s02 and s35 are test fixtures; s07, s09 and s35 are clients) | no |
| Uses built on these formats (Sigstore, C2PA, S/MIME, code signing) | ## Wedge & non-goals | none (s32 and s33 name git commits and packages only in their "so that"; their criteria stay at the format) | no |
| Bindings for other languages and the CLI tool (V2) | ## Wedge & non-goals | none (no `command` surface; s37 notes rule out a binary) | no |
| Repairing a malformed PDF | ## Wedge & non-goals | none (s04 criterion 3 refuses) | no |

## Checks
- [x] Exclusions: no story revives an excluded item, under any name: a PRD's graveyard feature or a brief's non-goal.
- [x] No technical layer is dressed as a story, and contract stories meet their conditions. s01, s02, s03, s04, s05, s07 and s09 each have at least two dependents and an observable test.
- [ ] Every criterion can be checked by one test. See the majors below.
- [x] Dependency order: no dependency on a later or unknown id. All 37 `Depends on` lines were checked.
- [x] Complexity: no 5, and every 4 names its risk (s02, s07, s13, s15, s17, s18, s22, s24, s26, s30, s32, s35, s36).
- [x] Ids: `s<number>-<slug>`, unique, numbered s01–s37 in file order.
- [x] Owns: every story declares one, and no two stories without a dependency between them hold overlapping entries. These shared entries are all ordered by a dependency chain:
  - `crates/nacre-pdf/` (s04→s05).
  - `crates/nacre-pades/` (s06→s08→s11→s12).
  - `crates/nacre-revocation/` and `revocation.md` (s09→s10).
  - `crates/nacre-validate/` and `pades.md` (s14→…→s18).
  - `conformance/` against `conformance/campaign/` and `conformance/corpus/foreign/` (s18 and s19 both reach s02).
  - `crates/nacre-cades/` (s21→s22), `crates/nacre-asic/` (s23→s27), `crates/nacre-xades/` (s25→s26), `crates/nacre-jades/` (s29→s30).
  - `crates/nacre-sig/`, `README.md` and `CHANGELOG.md` (s37 reaches s20 through s27→s23→s22→s21).
- [x] Surface: every story has a line; only `endpoint` and `—` are used, and Platform `lib, cli` admits both.
- [x] Owned records: no `Fixes` line, and no ADR that supersedes another.

## Findings
- **major — s13, s20 — Neither story proves success metric 1.** That metric asks for DSS `TOTAL_PASSED` at B, T, LT and LTA on a PDF signed with the YubiKey. s13's manual YubiKey run is logged in `MANUAL.md` "avec le rapport de DSS" at no stated level. s13's CI check stops at `PAdES-BASELINE-B` with SoftHSM. s20's `examples/sign_blta.rs` runs against SoftHSM only. So no story holds the wedge's proof (the four levels, YubiKey-signed, DSS XML reports kept). The capability exists; the evidence the brief defines success by does not.
- **major — s13, s20 — Both need CI changes outside their Owns.**
  - s13 criterion 2 ("Dans la CI, un PDF signé par une clé SoftHSM…") needs SoftHSM provisioned in a workflow.
  - s20 criterion 2 needs the example run in CI against SoftHSM and the s02 harness.
  - Both workflows, `.github/workflows/ci.yml` (s01) and `.github/workflows/conformance.yml` (s02), belong to other stories.
  - s20's `examples/sign_blta.rs` has no stated location. A root `examples/` is not in its Owns.
  - Either add the files to Owns, or say in s01/s02 that SoftHSM and example runs are picked up without editing the workflows (as s01 criterion 5 does for fuzz targets).
- **major — header (line 7), s20 — The fallback in the header cannot happen under the dependency graph.** The header says "s01 à s13 puis s20 sortent sans la validation". But s20 `Depends on` s19, which chains back through s18–s14. s20 criterion 1 also exposes a `validate` feature, and criterion 2 validates the signed PDF. The brief's fallback (`cms`, `pades`, `tsp`, `pkcs11` out alone) has no story that delivers it.
- **major — s23 — Criterion 2 accepts the indication alone.** "Plusieurs fichiers donnent un ASiC-E … DSS le déclare valide" checks only the indication. Premise 4 requires the exact level, never the indication alone; s23 criterion 1 and s27 both give the level.
- **major — s04, s06, s10, s12, s13 — Criteria no single test can check as written:**
  - s04 criterion 4: "erreur bornée en temps et en mémoire" gives no bound.
  - s06 criterion 5: "elle est calculée, et non une constante arbitraire" is a code-review statement, not an observable result.
  - s10 criterion 3: "sort de la tolérance" gives no value for the tolerance.
  - s12 criterion 3: "`extend` ne décide jamais quand il doit être appelé" has no input or output.
  - s13 criterion 4: "effacé de la mémoire après usage (`zeroize`)" names no observable check. The logging half is testable.
- **major — s10, s21, s31, s32, s33, s34 — Attack-list criteria are open-ended.** "Les attaques connues sont listées" (or "les attaques OCSP connues") names no set, so no test can tell when it is done. s03, s07, s24 and s28 do it right by naming the attacks. Because the header says a feature ships only once every listed attack is rejected, an unbounded list leaves the ship condition undefined.
- **major — s16 — The "chaîne contournée" attack has no corpus case.** The brief's accepted finding 4 names chain bypass among the CMS/X.509 attacks that must each have a rejected corpus case. s03's list leaves it out, and s16 has no attack criterion or attacks file.
- **minor — s19 — The Surface does not fit the story.** s19 is marked `endpoint` but adds corpus files and changes no public call. With `QA stage: surfaces` it would go to QA with an endpoint driver and nothing to call; `—` fits better.
- **minor — s19 — It may edit files it does not own.** Criterion 2 runs the s18 campaign on the enriched corpus. If the campaign lists its inputs, that edits `conformance/campaign/`, which s19 does not own. Say in the notes whether the campaign picks up `conformance/corpus/foreign/` on its own.
- **minor — s10 — The notes make a claim this review could not check.** They say "Les structures OCSP sont absentes de RustCrypto sous une forme stable". RustCrypto's formats repository publishes an `x509-ocsp` crate. If that counts as RustCrypto's X.509 layer, writing OCSP structures on `der` brushes the first non-goal. See Not verified.
- **minor — none (gap map) — No story carries the brief's quality attributes.** The brief sets signing a 10 MB PDF in under 1 s and validating in under 2 s, offline. These are defaults in the gap map, not a premise, so they are not a coverage gap.
- **minor — s25–s27, s29, s30 — No attacks file or hostile-input criterion for XAdES/JAdES.** The header's rule (one attacks list per format) would call for one. Their parsing leans on s24 and s28, which partly covers it.

## Not verified
- **Whether "X.509 stays with RustCrypto" also covers RFC 5280 path validation (s16) and OCSP structures (s10).** s16's notes read the non-goal as "model and encoding, not judgement". Neither the brief nor ADR-0001 settles that. If a person reads the non-goal more broadly, s16 or s10 revives it, which would be critical. The owner should confirm the reading, and check the actual state of `x509-ocsp`.
- **The state of outside crates and tools** (`cms`, `x509-cert`, `x509-ocsp`, `cryptoki`, `ureq`, DSS REST API versions). There is no network access and no code in scope. Claims about them in the notes were taken as written.
- **Patelle's files and ADRs** cited in the notes (`../patelle/lib/src/signer/`, `../patelle/conformance/dss/`, Patelle ADR-0008, ADR-0011, Patelle s02). They are outside this repository and outside scope, so it is unchecked that they exist and say what the notes claim.
- **Whether "published" in P7 means more than being in the public repository.** For example, a licence or README section for the corpus. No story states one; P7 was counted covered on the repository alone.
- **Whether s14's "toutes les attaques publiées (Mladenov et al. 2019–2021)" names a closed set.** The extent of that literature was not checked against the corpus the criterion asks for.
- **Success metric 3 (Patelle switches to Nacre and its own campaign passes).** It happens in Patelle's repository, as s20's notes say, and cannot be checked from these stories.
- **Story size.** Only the scores were judged. Whether s04 and s18 stay under about ten plan tasks cannot be told before planning.

Max severity: major
Stories ready: yes
