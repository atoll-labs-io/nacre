# Attaques connues — PAdES (PDF signé)

Format : signature PAdES dans un PDF (ETSI EN 319 142-1, ISO 32000-2 § 12.8), crate `crates/nacre-validate/`.

Chaque attaque traitée par s14 a son cas dans le corpus `crates/nacre-validate/tests/corpus/attacks/` et son test de rejet dans `crates/nacre-validate/tests/attacks.rs`. Chaque fichier est `unsigned.pdf` doté d'une signature qui n'a qu'un seul défaut ; quand un CMS est présent, il est correctement signé sur les octets que nomme sa `/ByteRange` : aucune autre règle ne peut répondre à la place de celle qui est visée. Le corpus se régénère par `cargo run -p nacre-validate --example forge_pades_attacks -- crates/nacre-validate/tests/corpus/attacks` ; la sortie est déterministe.

La validation applique ses contrôles dans un ordre fixe (`crates/nacre-validate/src/validate.rs`), pour que chaque cas atteigne la règle qui le nomme :

1. `/V` désigne un dictionnaire ;
2. `/SubFilter` vaut `/ETSI.CAdES.detached` ou `/adbe.pkcs7.detached` ;
3. `/Contents` est une chaîne non vide ;
4. `/ByteRange` est un tableau de quatre entiers positifs `[a b c d]` ;
5. `a` vaut 0 ;
6. la seconde plage ne commence pas avant la fin de la première ;
7. la seconde plage ne dépasse pas la fin du fichier ;
8. l'intervalle entre les deux plages est exactement la chaîne hexadécimale de `/Contents`, `<` et `>` compris ;
9. les octets signés s'arrêtent à la fin d'une révision ;
10. cette révision est la dernière (règle provisoire, voir plus bas) ;
11. `/Contents` contient une seule `SEQUENCE` DER suivie uniquement de zéros ;
12. empreinte des deux plages, puis vérification CMS (`nacre-cms`).

Tout défaut des contrôles 1 à 11 rend `TOTAL_FAILED` / `FORMAT_FAILURE`.

| Attaque (publication) | Variante | Cas du corpus | Test de rejet | Story | Résultat |
| --- | --- | --- | --- | --- | --- |
| USF, *Universal Signature Forgery* (Mladenov, Mainka, Meyer zu Selhausen, Grothe, Schwenk, *1 Trillion Dollar Refund: How To Spoof PDF Signatures*, ACM CCS 2019) | `/Contents` absent | `usf-contents-missing.pdf` | `usf_contents_missing_is_rejected` | s14 | `Defect::ContentsMissing` |
| USF (CCS 2019) | `/Contents null` | `usf-contents-null.pdf` | `usf_contents_null_is_rejected` | s14 | `Defect::ContentsMissing` |
| USF (CCS 2019) | `/Contents <>`, signature vide | `usf-contents-empty.pdf` | `usf_contents_empty_is_rejected` | s14 | `Defect::ContentsMissing` |
| USF (CCS 2019) | emplacement de signature laissé à zéro | `usf-contents-zeros.pdf` | `usf_contents_zeros_is_rejected` | s14 | `Defect::ContentsNotDer` |
| USF (CCS 2019) | `/ByteRange` absent | `usf-byterange-missing.pdf` | `usf_byterange_missing_is_rejected` | s14 | `Defect::ByteRangeMalformed` |
| USF (CCS 2019) | `/ByteRange null` | `usf-byterange-null.pdf` | `usf_byterange_null_is_rejected` | s14 | `Defect::ByteRangeMalformed` |
| USF (CCS 2019) | `/ByteRange` à trois entiers | `usf-byterange-short.pdf` | `usf_byterange_short_is_rejected` | s14 | `Defect::ByteRangeMalformed` |
| USF (CCS 2019) | `/ByteRange` incohérent : ne part pas de l'octet 0 | `byterange-not-from-start.pdf` | `byterange_not_from_start_is_rejected` | s14 | `Defect::ByteRangeNotFromStart` |
| USF (CCS 2019) | `/ByteRange` incohérent : plages qui se chevauchent | `byterange-overlap.pdf` | `byterange_overlap_is_rejected` | s14 | `Defect::ByteRangeOverlap` |
| USF (CCS 2019) | `/ByteRange` incohérent : plage hors du fichier | `byterange-outside-file.pdf` | `byterange_outside_file_is_rejected` | s14 | `Defect::ByteRangeOutsideFile` |
| USF (CCS 2019) | `/ByteRange` incohérent : la dernière ligne `%%EOF` n'est pas signée | `byterange-not-whole-file.pdf` | `byterange_not_whole_file_is_rejected` | s14 | `Defect::ByteRangeNotWholeFile` |
| SWA, *Signature Wrapping Attack* (CCS 2019) | l'intervalle non signé avale la fin du dictionnaire `/Sig` et `endobj`, place où l'attaquant glisse son contenu | `swa-wrapped.pdf` | `swa_wrapped_is_rejected` | s14 | `Defect::GapNotContents` |
| ISA, *Incremental Saving Attack* (CCS 2019) | révision ajoutée après la signature, qui remplace l'arbre des pages | `isa-appended-revision.pdf` | `isa_appended_revision_is_rejected` | s14 | `Defect::LaterRevision` (provisoire) |
| ISA (CCS 2019) | objet ajouté après `%%EOF`, sans section de références croisées ni trailer | `isa-no-xref.pdf` | `isa_no_xref_is_rejected` | s14 | `Error::Pdf(TrailingData)`, `ErrorKind::InvalidInput` |
| Shadow *hide* (Mainka, Mladenov, Rohlmann, *Shadow Attacks: Hiding and Replacing Content in Signed PDFs*, NDSS 2021) | contenu caché dans le document avant la signature, révélé par une révision ultérieure | à écrire par s15 | — | s15 | — |
| Shadow *replace* (NDSS 2021) | objets remplacés par une révision ultérieure (polices, formulaires) | à écrire par s15 | — | s15 | — |
| Shadow *hide-and-replace* (NDSS 2021) | document entier remplacé par une révision ultérieure | à écrire par s15 | — | s15 | — |
| EAA, *Evil Annotation Attack* (Rohlmann, Mladenov, Mainka, Schwenk, *Breaking the Specification: PDF Certification*, IEEE S&P 2021) | annotation ajoutée à un document certifié | à écrire par s15 | — | s15 | — |
| SSA, *Sneaky Signature Attack* (IEEE S&P 2021) | signature d'approbation ajoutée à un document certifié, dont l'apparence change le contenu | à écrire par s15 | — | s15 | — |

Jusqu'à s15, les attaques *shadow*, EAA et SSA passent toutes par une révision ajoutée après la signature visée : la règle provisoire `Defect::LaterRevision` les rejette déjà, faute de savoir qualifier ce que change une révision ultérieure. s15 remplace cette règle et écrit leurs cas.

## Hors de ce fichier

- **Chaîne de certification** : juger la chaîne, l'usage des clés et la validité des certificats relève de s16 ; une signature intègre finit donc `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`, jamais `TOTAL_PASSED`.
- **Révocation** : s17.
- **Horodatages de document** (`/SubFilter /ETSI.RFC3161`) : ignorés par `validate` jusqu'à s18, qui les juge ; ils n'apparaissent pas dans le résultat.
- **Règle provisoire `LaterRevision`** : une signature suivie d'une révision ultérieure est `TOTAL_FAILED`, là où DSS juge `TOTAL_PASSED` les deux signatures d'un PDF signé deux fois par Nacre. Faux négatif connu, jamais un faux valide ; s15 remplace cette seule branche (`covers_last_revision` dans `crates/nacre-validate/src/validate.rs`) par sa qualification des révisions.
- **Attaques sur le CMS lui-même** : `docs/security/attacks/cms.md`.
- **PDF hostile** (tronqué, octets altérés) : refusé par le lecteur strict de `nacre-pdf`, testé par `truncated_and_flipped_inputs_never_panic` dans `crates/nacre-validate/tests/hostile.rs` et exploré par la cible de fuzzing `crates/nacre-validate/fuzz/`.
