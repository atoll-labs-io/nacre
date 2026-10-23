# Attaques connues — PAdES (PDF signé)

Format : signature PAdES dans un PDF (ETSI EN 319 142-1, ISO 32000-2 § 12.8), crate `crates/nacre-validate/`.

Chaque attaque traitée par s14 et s15 a son cas dans le corpus `crates/nacre-validate/tests/corpus/attacks/` et son test de rejet dans `crates/nacre-validate/tests/attacks.rs`. Chaque fichier est `unsigned.pdf` doté d'une signature qui n'a qu'un seul défaut ; quand un CMS est présent, il est correctement signé sur les octets que nomme sa `/ByteRange` : aucune autre règle ne peut répondre à la place de celle qui est visée. Le corpus se régénère par `cargo run -p nacre-validate --example forge_pades_attacks -- crates/nacre-validate/tests/corpus/attacks` ; la sortie est déterministe.

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
10. `/Contents` contient une seule `SEQUENCE` DER suivie uniquement de zéros ;
11. empreinte des deux plages, puis vérification CMS (`nacre-cms`) ;
12. chaque révision postérieure est qualifiée (`crates/nacre-validate/src/revisions.rs`, règles plus bas).

Tout défaut des contrôles 1 à 10 rend `TOTAL_FAILED` / `FORMAT_FAILURE`. Le contrôle 12 ne s'applique qu'à une signature dont l'empreinte et le CMS sont vérifiés : une révision refusée ou illisible rend `TOTAL_FAILED` / `FORMAT_FAILURE` avec `Defect::RevisionNotAllowed`, `digest_verified` et `signature_verified` restant vrais. Une signature que sa propre révision refuse en tant que signature (la SSA, ou toute signature ajoutée sous DocMDP 1) rend de même `TOTAL_FAILED` / `FORMAT_FAILURE`, avec `Defect::AddedByRevisionNotAllowed` : elle ne se lit jamais comme saine prise seule. Une signature ajoutée dans une révision refusée pour une autre raison (un remplissage sans DocMDP, par exemple) est jugée sur ses seuls octets signés et les révisions qui la suivent, comme le fait l'EN 319 102-1 (`second_signer_beside_a_refused_fill_is_judged_alone`, `signature_added_under_p1_is_refused_with_its_revision`). Les cas du corpus visés par le contrôle 12 portent donc un CMS correct.

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
| ISA, *Incremental Saving Attack* (CCS 2019) | révision ajoutée après la signature, qui remplace l'arbre des pages | `isa-appended-revision.pdf` | `isa_appended_revision_is_rejected` | s14, s15 | `Defect::RevisionNotAllowed` |
| ISA (CCS 2019) | objet ajouté après `%%EOF`, sans section de références croisées ni trailer | `isa-no-xref.pdf` | `isa_no_xref_is_rejected` | s14 | `Error::Pdf(TrailingData)`, `ErrorKind::InvalidInput` |
| Shadow *hide* (Mainka, Mladenov, Rohlmann, *Shadow Attacks: Hiding and Replacing Content in Signed PDFs*, NDSS 2021) | contenu caché dans le document avant la signature, révélé par une révision ultérieure qui ne fait que repointer la table de références croisées vers un corps plus ancien | `shadow-hide.pdf` | `shadow_hide_is_rejected` | s15 | `Defect::RevisionNotAllowed`, objet 6 refusé |
| Shadow *replace* (NDSS 2021) | police de la page redéfinie par une révision ultérieure | `shadow-replace.pdf` | `shadow_replace_is_rejected` | s15 | `Defect::RevisionNotAllowed`, objet 5 refusé |
| Shadow *replace* (NDSS 2021) | champ de formulaire rempli après la signature d'un document non certifié | `shadow-form-field.pdf` | `shadow_form_field_is_rejected` | s15 | `Defect::RevisionNotAllowed` |
| Shadow *replace* (NDSS 2021) | objet libre auquel la page signée renvoyait déjà, défini après la signature | `shadow-late-definition.pdf` | `shadow_late_definition_is_rejected` | s15 | `Defect::RevisionNotAllowed`, objet 50 refusé |
| Shadow *replace* (NDSS 2021) | document certifié `/P 2` dont la page signée renvoyait à l'objet libre 50, défini après la signature comme apparence d'un champ rempli : la page le dessine aussi | `shadow-fill-late-definition.pdf` | `shadow_fill_late_definition_is_rejected` | s15 | `Defect::RevisionNotAllowed`, objet 50 refusé |
| Shadow *replace* (NDSS 2021) | flux à la fois dans `/DSS` et dessiné par la page, redéfini après la signature comme une mise à jour du `/DSS` | `shadow-dss-page.pdf` | `shadow_dss_page_is_rejected` | s15 | `Defect::RevisionNotAllowed`, objet 7 refusé |
| Shadow *hide-and-replace* (NDSS 2021) | catalogue et arbre des pages fantômes écrits avant la signature, désignés par le `/Root` d'une révision ultérieure | `shadow-hide-and-replace.pdf` | `shadow_hide_and_replace_is_rejected` | s15 | `Defect::RevisionNotAllowed`, catalogue 7 refusé |
| EAA, *Evil Annotation Attack* (Rohlmann, Mladenov, Mainka, Schwenk, *Breaking the Specification: PDF Certification*, IEEE S&P 2021) | annotation `/FreeText` ajoutée à un document certifié `/P 2` | `eaa-freetext.pdf` | `eaa_freetext_is_rejected` | s15 | `Defect::RevisionNotAllowed` |
| SSA, *Sneaky Signature Attack* (IEEE S&P 2021) | signature d'approbation ajoutée à un document certifié `/P 2`, son widget visible dessinant sur la page | `ssa-visible-signature.pdf` | `ssa_visible_signature_is_rejected` | s15 | `Defect::RevisionNotAllowed` pour la certification, `Defect::AddedByRevisionNotAllowed` pour `Sneaky` |
| SSA, champ et widget séparés | la même signature, son champ `/FT /Sig` et son widget visible écrits comme deux objets (`/Kids`, `/Parent`) | `ssa-split-widget.pdf` | `ssa_split_widget_is_rejected` | s15 | idem |
| SSA en deux temps | une révision ajoute au document certifié `/P 2` un champ de signature vide et visible, la suivante le signe | `ssa-empty-field-signed.pdf` | `ssa_empty_field_signed_is_rejected` | s15 | idem |

## Qualification des révisions postérieures

Chaque révision postérieure à une signature figure dans son résultat (`later_revisions`), avec les objets qu'elle change. Elle est comparée à la précédente sur les objets atteignables depuis le catalogue, jamais sur le rendu ; un flux est comparé par son dictionnaire et ses octets bruts. Est *inerte* ce que seuls `/DSS` ou `/Metadata` du catalogue atteignent ; le reste est *vivant*, y compris un objet atteint à la fois par `/DSS` et par une page. Un `/Root` qui change refuse la révision d'emblée. Sinon chaque objet vivant changé doit correspondre à une ligne :

| Objet | Différence permise | Type |
| --- | --- | --- |
| catalogue | `/DSS`, `/Metadata`, `/Extensions`, `/AcroForm` (jugé à la ligne suivante) | `Dss` si `/DSS` change |
| AcroForm, ou son tableau `/Fields` | `/Fields` garde chaque élément et n'ajoute que de nouveaux champs de signature ; `/SigFlags` | — |
| page existante, ou son tableau `/Annots` | `/Annots` seul, garde chaque élément, n'ajoute que des widgets de nouveaux champs de signature | — |
| champ de signature vide existant | gagne `/V` (et `/AP`, `/AS`, le drapeau Locked de `/F`), dictionnaire de signature dont la `/ByteRange` finit avec la révision | `Signature` ou `DocumentTimestamp` |
| champ non signature terminal, ou son widget | `/V`, `/AS`, `/AP` seuls, sous DocMDP 2 ou 3, champ qu'aucun verrou FieldMDP ne couvre | `FormFill` |

Un objet vivant nouveau n'est admis que s'il est un nouveau champ de signature (widget fusionné, `/FT /Sig`), son dictionnaire de signature, ou un objet atteint seulement depuis le `/AP` ou le `/V` d'un champ admis, et si tout objet qui le référence est lui-même admis. Sont refusés quoi qu'il arrive : une signature d'approbation sous DocMDP 1 ; une signature visible sur un document certifié dont le champ n'existait pas dans l'état certifié, la SSA : un widget de ce champ, le champ lui-même s'il est fusionné ou l'un de ses `/Kids`, a un `/Rect` d'aire non nulle et n'est ni Hidden ni NoView, que le champ soit ajouté par la révision qui signe ou par une révision antérieure. Signer un champ visible présent dans l'état certifié reste permis. Une révision dont l'état ne se lit pas est `Unreadable`, et refusée comme une révision non permise. Au-delà de 64 révisions après la plus ancienne signée, `validate` rend `Error::TooManyRevisions`. Le niveau DocMDP de chaque état se lit avec un seul résolveur, chaque flux d'objets décodé une fois ; un tableau `/Reference` de plus de 32 entrées (`Error::Limit` de `nacre-pdf`), ou toute permission illisible, rend `Unreadable` la révision qui l'introduit, ses objets changés restant listés, et les révisions suivantes sont jugées sous la permission la plus stricte, `/P 1` : la signature invisible `Late` ajoutée ensuite est refusée (`revision_over_the_docmdp_cap_lists_its_objects`).

## Hors de ce fichier

- **Chaîne de certification** : juger la chaîne, l'usage des clés et la validité des certificats relève de s16 ; une signature intègre finit donc `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`, jamais `TOTAL_PASSED`.
- **Révocation** : s17.
- **Horodatages de document** (`/SubFilter /ETSI.RFC3161`) : ignorés par `validate` jusqu'à s18, qui les juge ; ils n'apparaissent pas dans le résultat.
- **Écarts connus avec DSS et Acrobat**, plus stricts, jamais plus laxistes : une annotation ajoutée sous `/P 3` est refusée alors qu'ISO 32000 la permet ; un remplissage de formulaire sur un document non certifié est refusé, là où DSS et Acrobat peuvent n'émettre qu'un avertissement ; une révision refusée rend `TOTAL_FAILED` / `FORMAT_FAILURE`, comme tout défaut structurel, sans que la politique par défaut de DSS pour une modification après signature soit établie (s18, s19 comparent). Les noms de champs FieldMDP sont comparés en octets bruts de `/T` joints par `.`. Le cas B-LTA est prouvé sur le fichier de pyHanko (`lta_dss_and_timestamp_are_allowed`) ; s12 rejouera ce test sur sa propre sortie.
- **Attaques sur le CMS lui-même** : `docs/security/attacks/cms.md`.
- **PDF hostile** (tronqué, octets altérés) : refusé par le lecteur strict de `nacre-pdf`, testé par `truncated_and_flipped_inputs_never_panic` dans `crates/nacre-validate/tests/hostile.rs` et exploré par la cible de fuzzing `crates/nacre-validate/fuzz/`.
