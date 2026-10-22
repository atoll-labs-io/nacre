# Attaques connues — listes de révocation (CRL)

Format : CRL X.509 v2 (RFC 5280 §5), crate `crates/nacre-revocation/`.

Chaque attaque du jugement a son cas dans le corpus `crates/nacre-revocation/tests/corpus/attacks/` et son test de rejet dans `crates/nacre-revocation/tests/attacks.rs`. Chaque CRL est correctement signée, sauf son seul défaut, et liste la feuille `leaf.der` : une règle sautée répondrait « révoqué », jamais l'erreur attendue, et aucune autre règle ne peut répondre à la place de celle qui est visée. Le corpus se régénère par `cargo run -p nacre-revocation --example forge_crl_attacks -- crates/nacre-revocation/tests/corpus/attacks` ; la sortie est déterministe. Les cas sont jugés au 1er janvier 2027.

`Crl::status` applique ses contrôles dans un ordre fixe (`crates/nacre-revocation/src/crl.rs`, puis `src/verify.rs`), chacun arrêtant l'appel :

1. lecture du certificat (`Error::Certificate`) et du certificat émetteur (`Error::IssuerCertificate`) ;
2. émetteur de la CRL différent de l'émetteur du certificat ou du sujet du certificat émetteur (`Error::WrongIssuer`) ;
3. extension critique dans la CRL ou dans une de ses entrées (`Error::UnsupportedCriticalExtension`) ;
4. signature : `signatureAlgorithm` différent de `tbsCertList.signature` (`Error::AlgorithmMismatch`), `keyUsage` de l'émetteur sans `cRLSign` (`Error::IssuerNotCrlSigner`), algorithme ou clé non pris en charge (`Error::UnsupportedAlgorithm`, `Error::AlgorithmMismatch`), signature fausse sur les octets reçus du `tbsCertList` (`Error::SignatureInvalid`) ;
5. `nextUpdate` absent (`Error::MissingNextUpdate`) ou antérieur à la date de contrôle (`Error::Expired`) ;
6. recherche du numéro de série : `Revoked` avec date et motif, ou `NotRevoked`.

| Attaque | Cas du corpus | Test de rejet | Erreur rendue |
| --- | --- | --- | --- |
| CRL d'un autre émetteur : correctement signée par une autre AC, qui est donnée comme émetteur ; la feuille, elle, a été émise par `ca.der` | `wrong-issuer.der` (avec `other-ca.der`) | `crl_from_another_issuer_is_rejected` | `Error::WrongIssuer` |
| Émetteur renommé : un certificat qui porte la clé de l'AC sous un autre sujet, donné comme émetteur ; la signature de la CRL vérifie avec lui, seul le nom le trahit | `issuer-renamed.der` (avec `renamed-ca.der`) | `issuer_certificate_under_another_name_is_rejected` | `Error::WrongIssuer` |
| Signature invalide : la date de révocation de l'entrée avancée d'une minute après signature | `bad-signature.der` | `changed_byte_after_signing_is_rejected` | `Error::SignatureInvalid` |
| CRL périmée : `nextUpdate` au 1er juin 2026, rejouée après | `stale.der` | `stale_crl_is_rejected` | `Error::Expired { next_update }` |
| CRL sans `nextUpdate` : sa fraîcheur ne peut pas être montrée (RFC 5280 §5.1.2.5 l'exige) | `no-next-update.der` | `crl_without_next_update_is_rejected` | `Error::MissingNextUpdate` |
| CRL partitionnée : `issuingDistributionPoint` critique, qui restreint la portée de la liste | `critical-extension.der` | `critical_crl_extension_is_rejected` | `Error::UnsupportedCriticalExtension(2.5.29.28)` |
| Substitution d'algorithme : `signatureAlgorithm` externe, non signé, remplacé par `sha256WithRSAEncryption` sur une CRL ECDSA | `algorithm-substitution.der` | `algorithm_substitution_is_rejected` | `Error::AlgorithmMismatch` |
| Émetteur non habilité : même nom et même clé que l'AC, mais `keyUsage` réduit à `digitalSignature` (RFC 5280 §6.3.3 f) | `issuer-not-crl-signer.der` (avec `non-crl-signer-ca.der`) | `issuer_without_crl_sign_is_rejected` | `Error::IssuerNotCrlSigner` |
| CRL indirecte : `certificateIssuer` critique sur l'entrée de la feuille | `critical-entry-extension.der` | `critical_entry_extension_is_rejected` | `Error::UnsupportedCriticalExtension(2.5.29.29)` |

## Source HTTP : requêtes forcées (SSRF)

`HttpCrlSource` (fonctionnalité `http`) télécharge l'URL que nomme le point de distribution d'un certificat, qui peut venir de n'importe qui. Sans garde, un certificat ferait émettre une requête vers une adresse de son choix, interne au réseau de l'appelant. Ces cas n'ont pas de fichier dans le corpus : leurs tests, dans `crates/nacre-revocation/tests/http.rs`, forgent à l'exécution un certificat qui nomme l'URL voulue, et un serveur local sert une CRL valide, de sorte qu'un refus sauté se lirait comme un téléchargement réussi.

L'adresse est contrôlée sur les adresses que le nom résout, et la connexion se fait vers ces adresses-là, sans seconde résolution : pas de fenêtre de rebinding DNS. Un nom dont une seule adresse est refusée est refusé en entier. Les réglages de proxy sont ignorés, car un proxy résoudrait le nom hors de ce contrôle. `HttpCrlSource::allowing_loopback()` admet en plus `127.0.0.0/8` et `::1`, pour le banc de conformité qui sert ses CRL sur `127.0.0.1` ; le test du banc l'emploie, jamais le code de production.

| Attaque | Test de rejet | Erreur rendue |
| --- | --- | --- |
| Point de distribution sur la boucle locale (`http://127.0.0.1:<port>/…`), avec le constructeur par défaut ; le message ne cite pas l'URL | `loopback_point_is_refused_by_default` | `Error::NonPublicAddress` (genre `InvalidInput`) |
| Point de distribution sur une adresse privée écrite en clair (`10.1.2.3`, `fd00::1`), avec les deux constructeurs | `private_addresses_are_refused_even_with_loopback_allowed` | `Error::NonPublicAddress` |
| Redirection : un serveur répond `302` vers une URL qui sert une CRL valide ; aucune redirection n'est suivie | `redirect_is_not_followed` | `Error::Http(StatusCode(302))` |
| Plages refusées, une adresse par plage : `0.0.0.0/8`, boucle locale, RFC 1918, lien local `169.254.0.0/16` et `fe80::/10`, `100.64.0.0/10`, `192.0.0.0/24`, `198.18.0.0/15`, multicast, `240.0.0.0/4` et diffusion, `::`, `fc00::/7`, documentation, IPv4 dans IPv6 (`::ffff:0:0/96`, 6to4) ; en IPv6, seul `2000::/3` est public | `only_public_addresses_are_allowed` (test unitaire de `src/http.rs`) | — |

La source s'en tient à `http://` (pas d'`https`, pas de LDAP), borne la réponse à 16 Mio et l'appel à 30 s, et refuse ce qui n'est pas une CRL lisible ; un appelant qui veut plus de contrôle injecte sa propre `RevocationSource`. Il reste une requête GET aveugle vers une adresse publique qu'un certificat choisit.

## Hors de ce fichier

- **Entrée DER hostile** (tronquée, longueurs fausses, imbrication profonde) : rejetée par le décodage DER strict de `der` (longueurs définies, profondeur bornée), testée dans `crates/nacre-revocation/tests/hostile.rs` et explorée par la cible de fuzzing `crates/nacre-revocation/fuzz/`.
- **CRL v1** (sans champ `version`) : `x509-cert` exige ce champ, une CRL v1 est donc refusée comme DER invalide (`Error::Der`). Limite connue : toute AC actuelle émet des CRL v2.
- **Révocation dans le temps** : une date de révocation postérieure à la date de contrôle est rendue telle quelle dans `CrlStatus::Revoked` ; la comparer à une heure de signature, et juger une CRL émise après les faits, relève de s17.
- **Noms comparés à l'identique** : l'émetteur est comparé sur les noms décodés, plus strictement que la comparaison de RFC 5280 §7.1 ; l'écart ne peut produire qu'un `WrongIssuer` à tort, jamais un « non révoqué » à tort.
