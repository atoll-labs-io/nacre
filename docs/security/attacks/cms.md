# Attaques connues — CMS `SignedData`

Format : CMS `SignedData` (RFC 5652), crate `crates/nacre-cms/`.

Chaque attaque a son cas dans le corpus `crates/nacre-cms/tests/corpus/attacks/` et son test de rejet dans `crates/nacre-cms/tests/attacks.rs`. Chaque fichier est correctement signé, sauf son seul défaut : aucune autre règle ne peut répondre à la place de celle qui est visée. Le corpus se régénère par `cargo run -p nacre-cms --example forge_attacks -- crates/nacre-cms/tests/corpus/attacks` ; la sortie est déterministe.

La vérification applique ses contrôles dans un ordre fixe (`crates/nacre-cms/src/verify.rs`), pour que chaque cas atteigne la règle qui le nomme.

| Attaque | Cas du corpus | Test de rejet | Erreur rendue |
| --- | --- | --- | --- |
| Confusion d'algorithme : `sha256WithRSAEncryption` déclaré sur une signature ECDSA, avec une clé EC | `alg-confusion.der` | `algorithm_confusion_is_rejected` | `Error::AlgorithmMismatch` |
| Attributs signés absents : la signature porte directement sur l'empreinte du contenu | `signed-attrs-absent.der` | `absent_signed_attributes_are_rejected` | `Error::MissingSignedAttributes` |
| Attribut `message-digest` absent des attributs signés | `message-digest-absent.der` | `absent_message_digest_is_rejected` | `Error::MissingAttribute(messageDigest)` |
| Attributs signés dupliqués : deux `message-digest`, tous deux à la bonne valeur | `signed-attrs-duplicate.der` | `duplicated_signed_attribute_is_rejected` | `Error::DuplicateAttribute(messageDigest)` |
| `message-digest` incohérent avec le contenu | `message-digest-mismatch.der` | `inconsistent_message_digest_is_rejected` | `Error::MessageDigestMismatch` |
| `SignerIdentifier` qui ne désigne aucun certificat : numéro de série 2, le certificat porte le 1 | `sid-unknown.der` | `signer_identifier_designating_no_certificate_is_rejected` | `Error::SignerCertificateNotFound` |
| Substitution de certificat : un second certificat, même clé, même émetteur, même numéro, autre validité, désigné en premier par le `sid` ; `signing-certificate-v2` nomme l'original | `cert-substitution.der` | `substituted_certificate_is_rejected` | `Error::SigningCertificateMismatch` |
| Type de contenu incohérent : `eContentType` différent de l'attribut `content-type` | `content-type-mismatch.der` | `content_type_mismatch_is_rejected` | `Error::ContentTypeMismatch` |

## Hors de ce fichier

- **Chaîne contournée** (constat 4 du brief, issue #11) : juger la chaîne de certification, l'usage des clés et la validité des certificats relève de s16. `nacre-cms` ne couvre que sa part CMS, la substitution de certificat attrapée par `signing-certificate-v2` ; sa vérification prouve la signature et son lien à un certificat porté par le `SignedData`, pas la confiance en ce certificat.
- **Entrée DER hostile** (tronquée, longueurs fausses, imbrication profonde) : rejetée par le décodage DER strict de `der` (longueurs définies, profondeur bornée à 64), testée dans `crates/nacre-cms/tests/hostile.rs` et explorée par la cible de fuzzing `crates/nacre-cms/fuzz/`.
- **Attributs signés réordonnés** : `der` retrie un `SET OF` au décodage ; `nacre-cms` vérifie toujours les octets reçus, jamais un ré-encodage (`changed_signed_attribute_byte_fails` et `round_trip_is_byte_identical` dans `crates/nacre-cms/tests/read.rs`).
