# Attaques connues — horodatage RFC 3161

Format : réponse d'horodatage `TimeStampResp` et jeton `TimeStampToken` (RFC 3161), crate `crates/nacre-tsp/`.

Chaque attaque a son cas dans le corpus `crates/nacre-tsp/tests/corpus/` et son test de rejet dans `crates/nacre-tsp/tests/`. Chaque fichier forgé répond à `recorded/request.tsq` (même empreinte, même nonce) et reste correct, sauf son seul défaut : aucune autre règle ne peut répondre à la place de celle qui est visée. Le corpus forgé se régénère par `cargo run -p nacre-tsp --example forge_attacks -- crates/nacre-tsp/tests/corpus/attacks` ; la sortie est déterministe. Le cas de référence `attacks/valid.tsr` est vérifié par `forged_baseline_verifies`, et OpenSSL 3.6.5 l'accepte (`openssl ts -verify`).

La vérification applique ses contrôles dans un ordre fixe (`crates/nacre-tsp/src/token.rs`, puis `src/response.rs`) : statut, jeton présent, `SignedData` lu, contenu `id-ct-TSTInfo`, signature (`nacre-cms`), `signingCertificateV2` présent, usage étendu du certificat, `TSTInfo` lu, empreinte, puis nonce. Chaque cas atteint ainsi la règle qui le nomme.

| Attaque | Cas du corpus | Test de rejet | Erreur rendue |
| --- | --- | --- | --- |
| Rejeu sans nonce : un jeton valide pour la même empreinte, sans nonce, rejoué en réponse à une requête qui en portait un | `attacks/nonce-absent.tsr` | `replay_without_nonce_is_rejected` (`tests/attacks.rs`) | `Error::NonceMissing` |
| Rejeu d'une autre requête : un jeton authentique de la TSA du banc, présenté à une requête de même empreinte mais d'un autre nonce | `recorded/bench.tsr` | `other_nonce_is_rejected` (`tests/recorded.rs`) | `Error::NonceMismatch` |
| Jeton d'une autre empreinte : correctement signé, mais il horodate l'empreinte d'un autre contenu | `attacks/imprint-other.tsr` | `token_of_another_imprint_is_rejected` (`tests/attacks.rs`) | `Error::ImprintMismatch` |
| Certificat de TSA sans `id-kp-timeStamping` : même clé, mais le certificat porté est une AC sans usage étendu de clé (RFC 3161 §2.3 exige l'usage étendu critique, `timeStamping` seul) | `attacks/no-timestamping-eku.tsr` | `certificate_without_timestamping_is_rejected` (`tests/attacks.rs`) | `Error::NotTimestampingCertificate` |
| Signature altérée : un bit de la signature inversé | `attacks/signature-invalid.tsr` | `altered_signature_is_rejected` (`tests/attacks.rs`) | `Error::Cms(SignatureInvalid)` |
| Lien au certificat par `signingCertificate` v1 seul (empreinte SHA-1 que Nacre ne vérifie pas) : la substitution de certificat ne serait plus attrapée | `attacks/ess-v1-only.tsr` | `ess_v1_only_is_indeterminate` (`tests/attacks.rs`) | `Error::SigningCertificateMissing` |
| Contenu signé qui n'est pas un `TSTInfo` : une signature valide de la même clé sur un contenu `id-data`, cohérent avec son attribut `contentType`, présentée comme jeton | `attacks/content-type-other.tsr` | `content_other_than_tst_info_is_rejected` (`tests/attacks.rs`) | `Error::NotTstInfo` |
| Usage étendu non critique : le certificat de la TSA porte `timeStamping` seul, mais l'extension n'est pas marquée critique (RFC 3161 §2.3) | `attacks/eku-not-critical.tsr` | `non_critical_timestamping_purpose_is_rejected` (`tests/attacks.rs`) | `Error::NotTimestampingCertificate` |
| Usage étendu à plusieurs fins : l'extension critique porte `timeStamping` et `codeSigning`, alors que RFC 3161 §2.3 exige `timeStamping` seul | `attacks/eku-extra-purpose.tsr` | `timestamping_with_another_purpose_is_rejected` (`tests/attacks.rs`) | `Error::NotTimestampingCertificate` |
| Empreinte d'un autre algorithme : mêmes 32 octets que l'empreinte demandée, mais le `TSTInfo` les déclare SHA3-256 au lieu de SHA-256 | `attacks/imprint-algorithm-other.tsr` | `imprint_of_another_hash_algorithm_is_rejected` (`tests/attacks.rs`) | `Error::ImprintMismatch` |
| Paramètres d'algorithme d'empreinte ni absents ni `NULL` : SHA-256 suivi d'un `INTEGER 0` | `attacks/imprint-parameters-other.tsr` | `hash_parameters_other_than_null_are_rejected` (`tests/attacks.rs`) | `Error::ImprintMismatch` |

## Hors de ce fichier

- **Chaîne et validité du certificat de TSA** : juger la chaîne de certification, la révocation et la période de validité du certificat de la TSA relève de s16. `nacre-tsp` ne juge que son usage étendu.
- **`genTime` face à la date de contrôle** : la date d'horodatage est rendue, jamais comparée à l'horloge ni à une date de contrôle ; c'est le travail de la validation (s14 et suivantes).
- **Jetons SHA-384/512 et clés P-384** (FreeTSA, `recorded/freetsa.tsr`) : `nacre-cms` ne les vérifie pas encore, le jeton reste `Indeterminate` (`freetsa_response_is_indeterminate`) ; l'extension relève d'une issue sur `nacre-cms`.
- **Entrée BER** (longueurs indéfinies) : refusée par le décodage DER strict de `der`, en `InvalidInput`. Les entrées hostiles (tronquées, longueurs fausses, imbrication profonde, longueurs énormes) sont testées dans `crates/nacre-tsp/tests/hostile.rs` et explorées par la cible de fuzzing `crates/nacre-tsp/fuzz/`.
