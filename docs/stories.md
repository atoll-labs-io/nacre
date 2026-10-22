# Stories — Nacre

Each story is a slice a user can actually use, described precisely enough that an agent builds it without asking. Its id, `s<number>-<short-slug>`, names every file the pipeline writes for it and its branch `story/<id>`.

**Complexity scale** — 1: simple create/read/update/delete · 2: a form, storage and a list · 3: business logic or several states · 4: third-party integration, payments or roles · 5: real time, migrations or external systems. A 4 names its main risk. A 5 is split before anyone plans it.

Source : `docs/brief.md` (approuvé le 21/10/2026) et l'ADR-0001. Premier jalon (« Wedge ») : s01 à s20, échéance du 25/10/2026 ; repli du brief si la date passe : s01 à s13 puis s20 sortent sans la validation, et s14 à s19 suivent sans date. Familles suivantes : s21 à s37.

Disposition supposée, à confirmer par `/po-architect` : un workspace cargo dont le `Cargo.toml` racine déclare `members = ["crates/*"]` et n'est plus modifié après s01 ; une crate par famille sous `crates/nacre-<famille>/`, chacune avec ses tests, son corpus et sa cible de fuzzing (`crates/nacre-<famille>/fuzz/`) ; la façade publiée `nacre-sig` (`crates/nacre-sig/`, importée sous `nacre`) réexporte chaque famille derrière sa feature. `Cargo.lock` n'est pas versionné (bibliothèque), pour que deux stories qui ajoutent chacune une crate ne se bloquent pas. Chaque format suit sa liste d'attaques connues dans `docs/security/attacks/<format>.md` : un cas invalide par attaque dans le corpus, et la feature ne sort que si toutes sont rejetées (brief, constat 4).

## s01-workspace-contract — Le workspace et le contrat commun signataire, horodatage, révocation, rapport
**As** développeur Rust **I want** un contrat commun à toutes les familles (signataire, autorité d'horodatage, source de révocation, rapport de validation) **so that** chaque famille se branche sur les mêmes types et que Patelle n'apprenne qu'une API.

- **Complexity**: 2
- **Depends on**: none
- **Surface**: `endpoint`
- **Owns**: `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `crates/nacre-core/`, `.github/workflows/ci.yml`

### Acceptance criteria
- [ ] `cargo test --workspace`, `cargo clippy --workspace --all-targets --all-features -- -D warnings` et `cargo fmt --check` passent, en local et dans `.github/workflows/ci.yml`.
- [ ] `nacre-core` expose les traits `Signer` (algorithme, chaîne de certificats, signature d'une empreinte), `TimestampAuthority` (empreinte → jeton DER) et `RevocationSource` (certificat → CRL ou réponse OCSP DER), synchrones et sans I/O.
- [ ] `nacre-core` expose `ValidationReport` : indication (`TOTAL_PASSED`, `TOTAL_FAILED`, `INDETERMINATE`), sous-indication et niveau atteint, avec les noms d'EN 319 102-1.
- [ ] Un signataire logiciel de test (P-256, derrière la feature `test-signer`, jamais par défaut) signe une empreinte, et un test de contrat vérifie la signature avec `p256`.
- [ ] La CI lance, pour chaque dossier `crates/*/fuzz/` présent, chaque cible de fuzzing pendant 60 secondes, sans qu'une story ultérieure ait à modifier le workflow.
- [ ] `nacre-core` porte `#![forbid(unsafe_code)]` ; `Cargo.lock` est listé dans `.gitignore`.

### Notes for the agent
Story contrat : s03, s06, s07, s09, s13 et toutes les familles en dépendent. Reprendre les traits `Signer` et `TimestampAuthority` déjà écrits dans Patelle, branche `story/s01-sign-decision` (`../patelle/lib/src/signer/`, `../patelle/lib/src/tsa/`), en les généralisant ; ne rien modifier dans Patelle. MSRV : stable moins deux versions (brief, Interface contract), fixée dans `rust-toolchain.toml` et `rust-version`. Le `Cargo.toml` racine n'est plus touché après cette story : chaque crate déclare ses propres dépendances. Primitives, DER et X.509 viennent de RustCrypto (`p256`, `rsa`, `sha2`, `der`, `x509-cert`, `spki`), jamais réécrits (ADR-0001).

## s02-conformance-harness — Le banc de conformité : DSS, PKI de test et TSA locale
**As** développeur de Nacre **I want** un banc rejouable qui soumet un fichier signé à DSS local et lit le niveau rendu, avec une PKI et une TSA de test **so that** chaque feature prouve son niveau exact, jamais la seule indication.

- **Complexity**: 4
- **Depends on**: s01-workspace-contract
- **Surface**: —
- **Owns**: `conformance/`, `crates/nacre-conformance/`, `.github/workflows/conformance.yml`

### Acceptance criteria
- [ ] `conformance/compose.yaml` lance DSS à une version figée, une TSA RFC 3161 locale et un répondeur OCSP ; un serveur HTTP sert la CRL de la PKI de test.
- [ ] `conformance/pki/` génère, par un script rejouable, une racine, une intermédiaire, un certificat signataire, un certificat de TSA, un certificat révoqué et la CRL correspondante, avec des clés de test publiées pour ce seul usage.
- [ ] `nacre-conformance` (crate `publish = false`) soumet un fichier à l'API REST de validation de DSS, avec des ancres données, et rend l'indication, la sous-indication et le niveau lus dans le rapport simple ; le rapport XML est conservé sous `target/conformance/`.
- [ ] Un test soumet à DSS un PDF signé de référence fourni avec le banc et vérifie le niveau exact rendu.
- [ ] `.github/workflows/conformance.yml` lance le banc et les tests marqués conformance ; les rapports XML sont publiés comme artefacts de la CI.

### Notes for the agent
Story contrat : s06, s08, s11, s12, s13 et la validation en dépendent. Risque principal : l'API REST et le format du rapport de DSS changent selon la version ; figer l'image et la version, et tester la lecture du rapport sur un rapport réel enregistré. Reprendre le conteneur DSS de Patelle (`../patelle/conformance/dss/`, ADR-0008 de Patelle). Documents de test fictifs uniquement ; jamais la démo en ligne de DSS (brief, Security & abuse). Le PDF de référence peut venir de DSS lui-même (sa propre fonction de signature avec la clé de test).

## s03-cms-signed-data — Signer et vérifier une enveloppe CMS SignedData
**As** développeur Rust **I want** produire une enveloppe CMS SignedData détachée avec un `Signer`, et la relire et la vérifier **so that** PAdES, CAdES et l'horodatage reposent sur une seule implémentation CMS.

- **Complexity**: 3
- **Depends on**: s01-workspace-contract
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-cms/`, `docs/security/attacks/cms.md`

### Acceptance criteria
- [ ] Une empreinte et un `Signer` donnent un `SignedData` détaché DER (RFC 5652) avec les attributs signés `content-type`, `message-digest` et `signing-certificate-v2` ; `openssl cms -verify -binary -content <fichier>` l'accepte.
- [ ] Un profil peut interdire un attribut : avec le profil PAdES, `signing-time` n'est jamais écrit.
- [ ] Relire un `SignedData` DER produit par OpenSSL, puis vérifier sa signature, réussit ; changer un octet du contenu ou des attributs signés fait échouer la vérification.
- [ ] Une entrée DER hostile (tronquée, longueurs fausses, imbrication profonde) rend une erreur, jamais un panic ; une cible de fuzzing `crates/nacre-cms/fuzz/` existe.
- [ ] `docs/security/attacks/cms.md` liste les attaques connues (confusion d'algorithme, attributs signés absents ou dupliqués, `message-digest` incohérent, `SignerIdentifier` qui ne désigne pas le certificat), chacune avec son cas rejeté dans le corpus.

### Notes for the agent
Nacre écrit le modèle SignedData (ADR-0001) : ne pas utiliser la crate `cms` de RustCrypto, mais `der`, `x509-cert` et `spki` pour l'encodage et les certificats. Les attributs signés sont encodés en DER `SET OF` trié : c'est cet encodage qui est signé, pas celui du `[0] IMPLICIT`. Prévoir l'ajout ultérieur d'attributs non signés (s08 y range le jeton d'horodatage) sans re-signer.

## s04-pdf-read — Lire la structure d'un PDF réel ou le refuser clairement
**As** développeur Rust **I want** ouvrir un PDF et en lister les révisions et les champs de signature **so that** PAdES s'appuie sur un lecteur qui comprend les PDF réels ou les refuse avec une erreur claire.

- **Complexity**: 3
- **Depends on**: s01-workspace-contract
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-pdf/`

### Acceptance criteria
- [ ] Un PDF ouvert donne la liste de ses révisions (décalage de fin de chaque `%%EOF`), son trailer, son catalogue et ses champs de signature AcroForm.
- [ ] Les tables xref classiques, les flux xref, les flux d'objets et les xref hybrides sont lus ; le corpus `crates/nacre-pdf/tests/corpus/` contient des PDF produits par Word, LibreOffice, l'impression de Chrome et de Firefox, un PDF/A, un formulaire et un PDF déjà signé par un tiers, tous lus.
- [ ] Un PDF à xref cassée, à révision corrompue ou à objet introuvable rend une erreur qui nomme le défaut ; Nacre ne répare jamais un PDF.
- [ ] Une entrée hostile (boucles de références, flux de longueur fausse, imbrication profonde, PDF de plus de 50 Mo) rend une erreur bornée en temps et en mémoire, jamais un panic ; une cible de fuzzing existe.

### Notes for the agent
Spike du brief, fait dans la recherche de cette story : rassembler le corpus réel avant d'écrire le lecteur et consigner ce qu'il contient. Nacre écrit le lecteur au minimum que PAdES exige (ADR-0001) : pas de rendu, pas d'extraction de texte, pas d'édition de contenu. Décompression des flux : `FlateDecode` seulement, par une crate existante (`miniz_oxide`) ; tout autre filtre sur un flux xref ou un flux d'objets est refusé. Refuser plutôt que réparer est un non-goal du brief : signer un PDF réparé, c'est signer autre chose que ce que l'auteur a vu.

## s05-pdf-revision — Ajouter une révision incrémentale avec un emplacement de signature
**As** développeur Rust **I want** ajouter à un PDF une révision incrémentale qui porte un champ de signature, un `/Contents` réservé et son `/ByteRange` **so that** la signature couvre tout le fichier sans toucher un octet existant.

- **Complexity**: 3
- **Depends on**: s04-pdf-read
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-pdf/`

### Acceptance criteria
- [ ] Ajouter une révision à chaque PDF du corpus de s04 laisse les octets d'origine identiques, en préfixe du nouveau fichier.
- [ ] La révision ajoute un champ de signature invisible, son dictionnaire `/Sig` (`/Filter /Adobe.PPKLite`, `/SubFilter` au choix de l'appelant), un `/Contents` réservé à la taille demandée et un `/ByteRange` qui couvre tout le fichier sauf `/Contents`.
- [ ] L'API rend les plages à hacher, puis accepte la signature DER et l'écrit dans `/Contents` ; une signature plus grande que l'emplacement rend une erreur, sans fichier tronqué.
- [ ] La révision ajoutée suit le format xref du fichier d'origine (table ou flux) ; s04 relit le résultat sans erreur, et le PDF s'ouvre dans `qpdf --check` sans avertissement.
- [ ] Une révision sans signature (pour le `/DSS` de s11) s'ajoute par la même API.

### Notes for the agent
Le `/ByteRange` est écrit avant que la longueur finale ne soit connue : réserver des chiffres de largeur fixe et les remplir ensuite. Un PDF certifié (DocMDP) dont les permissions interdisent une nouvelle signature est refusé avec une erreur claire. Le `/Contents` est en hexadécimal, complété par des zéros.

## s06-pades-bb — Signer un PDF au niveau PAdES-BASELINE-B
**As** développeur Rust (Patelle d'abord) **I want** signer un PDF en PAdES baseline B-B avec un `Signer` **so that** DSS le déclare `PAdES-BASELINE-B`, sans les écarts d'`ades-rs`.

- **Complexity**: 3
- **Depends on**: s02-conformance-harness, s03-cms-signed-data, s05-pdf-revision
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-pades/`

### Acceptance criteria
- [ ] `sign` d'un PDF avec le signataire de test et la PKI de s02 rend un PDF que DSS déclare `TOTAL_PASSED` au niveau `PAdES-BASELINE-B`.
- [ ] Le `/SubFilter` est `ETSI.CAdES.detached` ; le CMS porte `signing-certificate-v2` et jamais `signing-time` ; l'heure de signature va dans `/M` du dictionnaire `/Sig`.
- [ ] Un PDF déjà signé reçoit une seconde signature dans une nouvelle révision, et DSS déclare les deux signatures `PAdES-BASELINE-B`.
- [ ] Les octets du PDF d'origine sont intacts en préfixe du résultat.
- [ ] La taille réservée pour `/Contents` suffit au niveau B-B ; elle est calculée, et non une constante arbitraire.

### Notes for the agent
Les écarts d'`ades-rs` à ne pas reproduire sont dans le brief (« Problem & evidence ») et dans l'ADR-0011 de Patelle : `signing-time` interdit par ETSI EN 319 142-1 (tableau 1), données de révocation rangées dans le CMS au lieu du `/DSS`. Prévoir dès maintenant la réserve de place que demandera l'horodatage de s08.

## s07-tsp-client — Obtenir et vérifier un jeton d'horodatage RFC 3161
**As** développeur Rust **I want** demander un jeton à une TSA et le vérifier **so that** les niveaux T, LT et LTA s'appuient sur un horodatage contrôlé.

- **Complexity**: 4
- **Depends on**: s02-conformance-harness, s03-cms-signed-data
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-tsp/`, `docs/security/attacks/tsp.md`

### Acceptance criteria
- [ ] Une empreinte donne une `TimeStampReq` DER (RFC 3161) avec un nonce et `certReq` ; la `TimeStampResp` est lue et son `TSTInfo` vérifié : empreinte identique, nonce identique, statut accordé, signature valide.
- [ ] Une réponse dont l'empreinte, le nonce ou la signature diffèrent est rejetée, chacune avec sa propre erreur.
- [ ] Sous la feature `http`, une implémentation de `TimestampAuthority` appelle une TSA par HTTP (`application/timestamp-query`) ; contre la TSA locale de s02, elle rend un jeton vérifié.
- [ ] Sans la feature `http`, la crate compile sans aucune dépendance réseau (`cargo tree` le montre).
- [ ] Une réponse hostile rend une erreur, jamais un panic ; une cible de fuzzing existe ; `docs/security/attacks/tsp.md` liste les attaques connues (rejeu sans nonce, jeton d'une autre empreinte, certificat de TSA sans `id-kp-timeStamping`), chacune avec son cas rejeté.

### Notes for the agent
Risque principal : les TSA réelles divergent (statuts, `certReq` ignoré, chaînes incomplètes). Garder un enregistrement de réponse de la TSA locale et d'au moins une TSA publique (FreeTSA, DigiCert) comme fixture, et ne jamais appeler une TSA publique depuis la CI. Le jeton est un `SignedData` : le lire avec `nacre-cms` (s03). Client HTTP bloquant de la feature `http` : `ureq` par défaut, à confirmer à `/po-architect`. Seule l'empreinte part vers la TSA, jamais le document.

## s08-pades-bt — Monter une signature PAdES au niveau B-T
**As** développeur Rust (Patelle d'abord) **I want** que la signature porte un horodatage de signature **so that** DSS la déclare `PAdES-BASELINE-T` et que sa date soit prouvée.

- **Complexity**: 2
- **Depends on**: s06-pades-bb, s07-tsp-client
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-pades/`

### Acceptance criteria
- [ ] `sign` au niveau T avec la TSA locale de s02 rend un PDF que DSS déclare `TOTAL_PASSED` au niveau `PAdES-BASELINE-T`.
- [ ] Le jeton est rangé dans l'attribut non signé `signature-time-stamp` du `SignerInfo`, et porte sur la valeur de signature.
- [ ] Une TSA injoignable ou une réponse refusée fait échouer `sign` avec une erreur qui nomme la TSA ; aucun PDF partiel n'est rendu.
- [ ] La taille réservée pour `/Contents` couvre le jeton ; un jeton trop grand rend une erreur claire.

### Notes for the agent
L'appel à la TSA passe par le trait `TimestampAuthority` (s01) : les tests unitaires injectent une fausse TSA, les tests de conformité la TSA locale.

## s09-revocation-crl — Récupérer et lire une CRL
**As** développeur Rust **I want** obtenir la CRL d'un certificat et savoir s'il y figure **so that** B-LT embarque les données de révocation et que la validation puisse les juger.

- **Complexity**: 3
- **Depends on**: s02-conformance-harness
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-revocation/`, `docs/security/attacks/revocation.md`

### Acceptance criteria
- [ ] Une CRL DER est lue : émetteur, `thisUpdate`, `nextUpdate`, numéros révoqués avec date et motif ; sa signature est vérifiée avec le certificat de l'émetteur.
- [ ] Sous la feature `http`, `RevocationSource` télécharge la CRL depuis le point de distribution du certificat ; contre la PKI de s02, le certificat révoqué y figure, le certificat signataire non.
- [ ] Une CRL d'un autre émetteur, à signature invalide ou périmée (`nextUpdate` passé à la date de contrôle) est signalée comme telle, sans être prise pour une réponse « non révoqué ».
- [ ] Une CRL hostile rend une erreur, jamais un panic ; une cible de fuzzing existe.

### Notes for the agent
X.509 et l'encodage DER restent à RustCrypto (`x509-cert` lit déjà la structure `CertificateList`) ; Nacre écrit la logique de récupération et de jugement. La date de contrôle est un paramètre, jamais l'horloge système en dur : la validation de s17 juge à la date prouvée par un horodatage.

## s10-revocation-ocsp — Interroger un répondeur OCSP
**As** développeur Rust **I want** obtenir une réponse OCSP signée pour un certificat **so that** B-LT et la validation acceptent aussi les PKI qui ne publient que de l'OCSP.

- **Complexity**: 3
- **Depends on**: s09-revocation-crl
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-revocation/`, `docs/security/attacks/revocation.md`

### Acceptance criteria
- [ ] Une `OCSPRequest` DER (RFC 6960) est construite pour un certificat et son émetteur, avec un nonce ; la `BasicOCSPResponse` est lue et sa signature vérifiée, que le répondeur soit l'autorité elle-même ou un répondeur délégué (`id-kp-OCSPSigning`).
- [ ] Contre le répondeur de s02, le certificat révoqué rend `revoked` avec sa date, le certificat signataire `good`.
- [ ] Une réponse d'un répondeur non autorisé, à nonce différent ou dont `thisUpdate` sort de la tolérance est rejetée, chacune avec sa propre erreur.
- [ ] Une réponse hostile rend une erreur, jamais un panic ; une cible de fuzzing existe ; les attaques OCSP connues sont ajoutées à `docs/security/attacks/revocation.md`.

### Notes for the agent
Même trait `RevocationSource` que s09 : l'appelant choisit OCSP, CRL, ou OCSP puis CRL en repli. Les structures OCSP sont absentes de RustCrypto sous une forme stable : les écrire sur `der` dans cette crate.

## s11-pades-blt — Monter une signature PAdES au niveau B-LT avec le dictionnaire /DSS
**As** développeur Rust (Patelle d'abord) **I want** que le PDF embarque les certificats et les données de révocation de la signature et de sa TSA dans `/DSS` **so that** DSS le déclare `PAdES-BASELINE-LT` et qu'il se vérifie sans réseau.

- **Complexity**: 3
- **Depends on**: s08-pades-bt, s10-revocation-ocsp
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-pades/`

### Acceptance criteria
- [ ] `sign` au niveau LT ajoute après la signature une révision qui porte `/DSS` avec `/Certs`, `/CRLs` et `/OCSPs` ; DSS la déclare `TOTAL_PASSED` au niveau `PAdES-BASELINE-LT`.
- [ ] `/DSS` couvre la chaîne du signataire et celle de la TSA, chacune avec sa donnée de révocation ; une entrée `/VRI` par signature est écrite.
- [ ] Rien n'est ajouté dans le CMS : les données de révocation ne vivent que dans `/DSS`.
- [ ] Un certificat dont la révocation ne peut être obtenue fait échouer le passage au niveau LT avec une erreur qui le nomme ; la signature B-T reste rendue à l'appelant.

### Notes for the agent
C'est l'écart principal d'`ades-rs` : son « B-LT » rangeait la révocation dans le CMS (brief, « Problem & evidence »). Les sources passent par `RevocationSource`, jamais par un appel réseau direct.

## s12-pades-blta — Monter une signature PAdES au niveau B-LTA et l'étendre plus tard
**As** développeur Rust (Patelle d'abord) **I want** ajouter un horodatage de document après `/DSS`, puis pouvoir en ajouter un nouveau plus tard **so that** DSS déclare le PDF `PAdES-BASELINE-LTA` et que sa preuve survive à l'expiration des certificats.

- **Complexity**: 3
- **Depends on**: s11-pades-blt
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-pades/`

### Acceptance criteria
- [ ] `sign` au niveau LTA ajoute une révision `/DocTimeStamp` (`/SubFilter /ETSI.RFC3161`) après `/DSS` ; DSS déclare le PDF `TOTAL_PASSED` au niveau `PAdES-BASELINE-LTA`.
- [ ] `extend` sur un PDF déjà LTA ajoute un `/DSS` mis à jour (révocation de la TSA précédente), puis un nouvel horodatage de document ; DSS déclare toujours `PAdES-BASELINE-LTA`.
- [ ] `extend` ne décide jamais quand il doit être appelé : c'est à l'appelant (brief, Domain model).
- [ ] Les octets de chaque révision précédente sont intacts en préfixe du résultat.
- [ ] Un PDF signé au niveau LTA avec deux TSA distinctes (une pour la signature, une pour le document) est accepté par DSS.

### Notes for the agent
Patelle exige deux TSA distinctes (son s02) : l'API laisse l'appelant choisir la TSA de chaque horodatage. La révision `/DocTimeStamp` reprend l'emplacement de signature de s05 avec un jeton RFC 3161 comme contenu.

## s13-pkcs11-signer — Signer avec une clé matérielle par PKCS#11
**As** développeur Rust (Patelle d'abord) **I want** un `Signer` qui signe avec une clé restée sur un jeton PKCS#11 (YubiKey, carte, HSM) **so that** la clé privée ne quitte jamais le matériel.

- **Complexity**: 4
- **Depends on**: s06-pades-bb
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-pkcs11/`

### Acceptance criteria
- [ ] Un `Signer` PKCS#11 ouvre une session sur un module donné, se connecte avec un PIN, trouve la clé et son certificat par libellé ou identifiant, et signe une empreinte en ECDSA P-256 (signature brute `r||s` convertie en DER) et en RSA PKCS#1 v1.5.
- [ ] Dans la CI, un PDF signé par une clé SoftHSM est déclaré `PAdES-BASELINE-B` par DSS.
- [ ] Un PIN faux rend une erreur qui donne l'état exposé par le jeton (peu d'essais restants, dernier essai, verrouillé) ; aucun panic, aucune signature.
- [ ] Le PIN est effacé de la mémoire après usage (`zeroize`) et n'apparaît dans aucun message d'erreur ni journal.
- [ ] Un essai manuel sur une YubiKey réelle (emplacement PIV 9c, `libykcs11`) est consigné dans `crates/nacre-pkcs11/MANUAL.md`, avec le rapport de DSS.

### Notes for the agent
Risque principal : les modules PKCS#11 réels divergent (`ykcs11` et OpenSC n'exposent pas les mêmes mécanismes ni les mêmes compteurs de PIN). Spike du brief « YubiKey PIV par PKCS#11 en ECDSA P-256 » : le faire dans la recherche, sur la vraie clé. Liaison PKCS#11 par `cryptoki`, la seule exception à `forbid(unsafe_code)` (brief, Security & abuse). Reprendre les tests SoftHSM de Patelle (`story/s01-sign-decision`). Les tests automatiques n'utilisent jamais la vraie YubiKey, pour ne pas user son compteur de PIN.

## s14-validate-integrity — Valider l'intégrité cryptographique d'une signature PAdES
**As** développeur Rust (Patelle d'abord) **I want** vérifier qu'une signature PAdES couvre bien le document et qu'elle est cryptographiquement valide **so that** aucune signature falsifiée ne passe pour valide.

- **Complexity**: 3
- **Depends on**: s06-pades-bb
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-validate/`, `docs/security/attacks/pades.md`

### Acceptance criteria
- [ ] `validate` d'un PDF signé en s06 rend un `ValidationReport` par signature, avec l'empreinte et la signature vérifiées.
- [ ] Un `/ByteRange` qui ne couvre pas tout le fichier sauf `/Contents`, qui se chevauche ou qui pointe hors du fichier rend `TOTAL_FAILED`, avec la sous-indication d'EN 319 102-1.
- [ ] Les attaques USF (signature vide, `/Contents` nul, `/ByteRange` absent ou incohérent), SWA (déplacement du `/ByteRange` pour envelopper un autre contenu) et ISA (révision ajoutée qui réécrit le contenu signé) du corpus `crates/nacre-validate/tests/corpus/attacks/` sont toutes rejetées.
- [ ] `docs/security/attacks/pades.md` liste toutes les attaques publiées contre les PDF signés (Mladenov et al. 2019–2021), chacune avec son cas du corpus et la story qui la rejette.
- [ ] Une entrée hostile rend une erreur, jamais un panic ; une cible de fuzzing existe.

### Notes for the agent
Les attaques et leurs fichiers d'exemple sont publiés (pdf-insecurity.org) ; n'utiliser que des PDF fictifs reconstruits avec la PKI de s02. Cette story ne juge ni la chaîne ni la révocation ni le niveau (s16 à s18) : sans chaîne jugée, l'indication finale reste `INDETERMINATE`, jamais `TOTAL_PASSED`.

## s15-validate-revisions — Juger chaque révision ajoutée après une signature
**As** développeur Rust (Patelle d'abord) **I want** que la validation signale et qualifie chaque révision postérieure à une signature **so that** les shadow attacks et les attaques sur les PDF certifiés soient détectées.

- **Complexity**: 4
- **Depends on**: s14-validate-integrity
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-validate/`, `crates/nacre-pdf/`, `docs/security/attacks/pades.md`

### Acceptance criteria
- [ ] Chaque révision postérieure à une signature est listée dans le rapport et qualifiée : autorisée (`/DSS`, horodatage de document, nouvelle signature, remplissage de champ permis par DocMDP) ou non autorisée, avec les objets qu'elle change.
- [ ] Les shadow attacks hide, replace et hide-and-replace du corpus sont toutes détectées : la signature est rendue `TOTAL_FAILED` ou `INDETERMINATE`, jamais `TOTAL_PASSED`.
- [ ] Les attaques EAA (*evil annotation attack*) et SSA (*sneaky signature attack*) sur les PDF certifiés du corpus sont toutes détectées.
- [ ] Une signature B-LTA de s12, qui ajoute `/DSS` et `/DocTimeStamp` après la signature, n'est pas signalée comme altérée.

### Notes for the agent
Risque principal : distinguer une révision légitime d'une révision malveillante. Les règles DocMDP (P=1, 2, 3) et FieldMDP décident de ce qui est permis ; toute révision qui touche un objet de contenu (page, flux, annotation non permise) est non autorisée. Comparer les objets de chaque révision avec ceux de la précédente, jamais le rendu : Nacre ne rend pas les PDF.

## s16-validate-chain — Construire et juger la chaîne de certificats vers une ancre déclarée
**As** développeur Rust (Patelle d'abord) **I want** que la validation construise la chaîne du signataire jusqu'à une ancre de confiance que je fournis **so that** une signature n'est « valide » que rattachée à une racine explicitement acceptée.

- **Complexity**: 3
- **Depends on**: s15-validate-revisions
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-validate/`

### Acceptance criteria
- [ ] Avec la racine de la PKI de s02 comme ancre, la chaîne du signataire de s06 est construite, depuis les certificats du CMS et de `/DSS`, et jugée valide.
- [ ] Sans ancre fournie, `validate` rend `INDETERMINATE` avec `NO_CERTIFICATE_CHAIN_FOUND`, jamais `TOTAL_PASSED` (brief, constat 5).
- [ ] Un certificat expiré à la date de contrôle, un usage de clé incompatible avec la signature (`digitalSignature` ou `nonRepudiation` absent) ou une contrainte de base violée rend la sous-indication d'EN 319 102-1 correspondante.
- [ ] La construction et le jugement de chaîne sont exposés par une API publique de `nacre-validate`, réutilisable par CAdES, XAdES et JAdES sans dépendre de PDF.

### Notes for the agent
Validation de chemin RFC 5280 écrite par Nacre sur les certificats de `x509-cert` (ADR-0001 : X.509 reste à RustCrypto pour le modèle et l'encodage, pas pour le jugement). La date de contrôle est un paramètre ; s17 la remplace par la date prouvée.

## s17-validate-revocation — Juger la révocation à la date prouvée par l'horodatage
**As** développeur Rust (Patelle d'abord) **I want** que la validation juge la révocation du signataire à la date prouvée par l'horodatage, avec les données de `/DSS` ou de `RevocationSource` **so that** une signature faite avant une révocation reste valide et une signature faite après soit refusée.

- **Complexity**: 4
- **Depends on**: s16-validate-chain, s12-pades-blta
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-validate/`

### Acceptance criteria
- [ ] Une signature B-T faite avant la révocation du certificat, avec une CRL postérieure à la révocation, reste valide ; une signature dont l'horodatage est postérieur à la révocation rend `TOTAL_FAILED` avec `REVOKED`.
- [ ] Sans horodatage (B-B), la révocation est jugée à la date de contrôle, et un certificat révoqué depuis rend `INDETERMINATE` (`REVOKED_NO_POE`).
- [ ] Les données de `/DSS` suffisent, sans réseau, pour juger un PDF B-LT ou B-LTA de s11 et s12 ; sans données et sans `RevocationSource`, l'indication est `INDETERMINATE` (`TRY_LATER` ou `REVOCATION_OUT_OF_BOUNDS_NO_POE`).
- [ ] La chaîne de la TSA est jugée comme celle du signataire.
- [ ] Ces cas sont confrontés à DSS par le banc de s02, et DSS rend la même indication et la même sous-indication.

### Notes for the agent
Risque principal : la logique de preuve d'existence (POE) d'EN 319 102-1, où DSS a ses interprétations. Spike du brief (constat 6), fait dans la recherche : confronter le rapport détaillé de DSS aux blocs de la norme sur une dizaine de cas limites et consigner, pour chaque divergence, si Nacre suit la norme ou DSS.

## s18-validate-level — Rendre le niveau AdES exact atteint, identique à DSS
**As** développeur Rust (Patelle d'abord) **I want** que la validation rende le niveau PAdES baseline exact atteint **so that** Patelle juge ses décisions sans DSS, avec le même verdict.

- **Complexity**: 4
- **Depends on**: s17-validate-revocation
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-validate/`, `conformance/campaign/`

### Acceptance criteria
- [ ] Les PDF de s06, s08, s11 et s12 sont rendus `PAdES-BASELINE-B`, `-T`, `-LT` et `-LTA`, chacun avec `TOTAL_PASSED`.
- [ ] Un PDF qui porte un attribut interdit par EN 319 142-1 (`signing-time`, comme ceux d'`ades-rs`) ou des données de révocation dans le CMS n'est jamais rendu au niveau baseline qu'il revendique.
- [ ] Les horodatages de signature et de document sont vérifiés (empreinte, chaîne de la TSA, révocation) ; un horodatage invalide fait tomber le niveau qu'il porte.
- [ ] `conformance/campaign/` lance la campagne du brief : sur tout le corpus, valide et invalide, attaques comprises, le verdict de `validate` (indication, sous-indication, niveau) est identique à celui de DSS dans 100 % des cas ; un seul écart fait échouer la campagne.
- [ ] Les rapports XML de DSS de chaque campagne sont conservés comme preuve.

### Notes for the agent
Risque principal : un écart de niveau avec DSS sur un cas limite ; la règle du brief n'en tolère aucun. S'appuyer sur les conclusions du spike de s17 pour chaque divergence connue.

## s19-foreign-corpus — Confronter la validation à des signatures produites par d'autres outils
**As** développeur de Nacre **I want** que le corpus de la campagne contienne des signatures produites par d'autres outils que Nacre **so that** l'accord avec DSS ne se limite pas aux angles morts de Nacre.

- **Complexity**: 2
- **Depends on**: s18-validate-level
- **Surface**: `endpoint`
- **Owns**: `conformance/corpus/foreign/`

### Acceptance criteria
- [ ] Le corpus contient des PDF signés par DSS, par pyHanko et par Adobe Acrobat, à chaque niveau baseline qu'ils savent produire, et des PDF signés publics dont la licence permet la redistribution, chacun avec sa source notée.
- [ ] La campagne de s18 passe sur ce corpus enrichi : verdict identique à DSS dans 100 % des cas.
- [ ] Chaque fichier ajouté est fictif ou public ; aucune donnée personnelle (brief, Security & abuse).

### Notes for the agent
Brief, constat 5 du pré-mortem. Les signatures pyHanko et DSS se produisent avec la PKI de s02 ; Acrobat demande un essai manuel, consigné comme la source du fichier. Un écart trouvé ici est un défaut de `validate`, à signaler par le `Issue tracker`, pas à masquer en retirant le fichier.

## s20-nacre-sig-milestone — Publier la façade nacre-sig du premier jalon
**As** développeur Rust (Patelle d'abord) **I want** ajouter la seule dépendance `nacre-sig` et n'activer que les features dont j'ai besoin **so that** Patelle signe et valide jusqu'à B-LTA par une API unique, sans compiler le reste.

- **Complexity**: 2
- **Depends on**: s13-pkcs11-signer, s19-foreign-corpus
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-sig/`, `README.md`, `CHANGELOG.md`

### Acceptance criteria
- [ ] `nacre-sig` (importée sous `nacre`) expose les features `cms`, `pades`, `tsp`, `validate`, `pkcs11` et `http`, aucune par défaut ; avec seulement `pades`, `cargo tree` ne montre ni `nacre-validate`, ni `nacre-pkcs11`, ni une dépendance réseau.
- [ ] Un exemple documenté (`examples/sign_blta.rs`) signe un PDF jusqu'à B-LTA avec un `Signer` PKCS#11 et la feature `http`, puis le valide ; il tourne dans la CI contre SoftHSM et le banc de s02.
- [ ] `cargo publish --dry-run -p nacre-sig` passe ; la publication reste faite par un humain (brief, Operations).
- [ ] Le `README.md` décrit les features, les licences MIT OR Apache-2.0, et avertit que `validate` n'a pas été relu par un tiers et ne doit pas servir de seule preuve hors d'atoll avant un audit externe (brief, constat 7).
- [ ] `CHANGELOG.md` ouvre la version 0.1.0.

### Notes for the agent
La bascule de Patelle sur Nacre (critère 3 du « Success metric ») se fait dans le dépôt de Patelle, pas ici : cette story livre ce que Patelle consomme. Les familles des stories s21 à s36 rejoignent la façade en s37.

## s21-cades-bb-bt — Signer et valider en CAdES baseline B-B et B-T
**As** développeur Rust **I want** signer un fichier quelconque en CAdES détaché, horodaté **so that** les documents qui ne sont pas des PDF aient aussi une signature avancée, déclarée `CAdES-BASELINE-T` par DSS.

- **Complexity**: 3
- **Depends on**: s20-nacre-sig-milestone
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-cades/`, `docs/security/attacks/cades.md`

### Acceptance criteria
- [ ] Un fichier et un `Signer` donnent une signature CAdES détachée (`.p7s`) que DSS déclare `TOTAL_PASSED` au niveau `CAdES-BASELINE-B`, puis `-T` avec un horodatage de signature.
- [ ] La signature CAdES porte `signing-time` et `signing-certificate-v2`, comme EN 319 122-1 l'exige, à l'inverse de PAdES.
- [ ] La validation de Nacre rend le même niveau et la même indication que DSS, intégrité, chaîne (s16) et révocation (s17) comprises.
- [ ] `docs/security/attacks/cades.md` liste les attaques connues, chacune avec son cas rejeté.

### Notes for the agent
Réutiliser `nacre-cms`, `nacre-tsp` et l'API publique de chaîne et de révocation de `nacre-validate` ; ne rien copier. Le jugement du niveau CAdES vit dans cette crate.

## s22-cades-blt-blta — Monter une signature CAdES aux niveaux B-LT et B-LTA
**As** développeur Rust **I want** qu'une signature CAdES embarque ses données de validation et un horodatage d'archive **so that** DSS la déclare `CAdES-BASELINE-LTA`.

- **Complexity**: 4
- **Depends on**: s21-cades-bb-bt
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-cades/`

### Acceptance criteria
- [ ] Une signature B-T reçoit les certificats et les révocations de sa chaîne et de celle de sa TSA ; DSS la déclare `CAdES-BASELINE-LT`.
- [ ] Un `archive-time-stamp-v3` avec son `ats-hash-index-v3` monte la signature à `CAdES-BASELINE-LTA` dans DSS ; un second horodatage d'archive s'ajoute plus tard sans casser le premier.
- [ ] La validation de Nacre rend le même niveau que DSS.

### Notes for the agent
Risque principal : le calcul de l'`ats-hash-index-v3` (EN 319 122-1, §5.5.3), où le moindre écart d'ordre ou d'encodage casse l'horodatage d'archive ; confronter chaque étape à DSS.

## s23-asic-cades — Empaqueter des fichiers signés en conteneur ASiC (CAdES)
**As** développeur Rust **I want** signer un ou plusieurs fichiers dans un conteneur ASiC-S ou ASiC-E avec une signature CAdES **so that** des lots de documents voyagent avec leur signature, déclarés valides par DSS.

- **Complexity**: 3
- **Depends on**: s22-cades-blt-blta
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-asic/`, `docs/security/attacks/asic.md`

### Acceptance criteria
- [ ] Un fichier donne un ASiC-S (`mimetype` en premier et non compressé, `META-INF/signature.p7s`) que DSS déclare `TOTAL_PASSED` au niveau CAdES demandé.
- [ ] Plusieurs fichiers donnent un ASiC-E avec `META-INF/ASiCManifest.xml` signé ; DSS le déclare valide.
- [ ] Un fichier ajouté, retiré ou modifié dans le conteneur fait échouer la validation de Nacre comme celle de DSS.
- [ ] Une archive hostile (traversée de chemin `../`, bombe de décompression, entrées en double) rend une erreur, jamais un panic ; une cible de fuzzing existe.

### Notes for the agent
Le ZIP est un format de conteneur, pas un format de signature : sa lecture passe par une crate existante (`zip`), à confirmer à `/po-architect`. Le manifeste ASiC-E est un XML simple, écrit ici sans dépendre de XML-DSig (s24).

## s24-xmldsig — Signer et vérifier en XML-DSig avec canonicalisation
**As** développeur Rust **I want** signer et vérifier un document XML en XML-DSig, avec canonicalisation **so that** XAdES, les factures électroniques et les listes de confiance reposent sur une implémentation XML-DSig de Nacre.

- **Complexity**: 4
- **Depends on**: s20-nacre-sig-milestone
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-xml/`, `docs/security/attacks/xml.md`

### Acceptance criteria
- [ ] Les canonicalisations C14N 1.0, C14N 1.1 et Exclusive C14N donnent, sur les vecteurs de test du W3C, la sortie attendue à l'octet près.
- [ ] Une signature enveloppée, enveloppante ou détachée, produite par Nacre, est vérifiée par `xmlsec1` ; une signature de `xmlsec1` est vérifiée par Nacre.
- [ ] Les attaques XML connues (signature wrapping, références par ID ambiguës, entités externes XXE, expansion d'entités, transformations XSLT ou XPath arbitraires) du corpus sont toutes rejetées et listées dans `docs/security/attacks/xml.md`.
- [ ] Seules les transformations d'une liste fermée sont acceptées ; toute autre rend une erreur.
- [ ] Une entrée hostile rend une erreur, jamais un panic ; une cible de fuzzing existe.

### Notes for the agent
Risque principal : la canonicalisation et le signature wrapping, deux sources classiques de faux « valide ». La lecture XML elle-même (l'équivalent de DER pour CMS) passe par une crate existante sans résolution d'entités externes ; Nacre écrit C14N et XML-DSig (ADR-0001). Choix de la crate à confirmer à `/po-architect`.

## s25-xades-bb-bt — Signer et valider en XAdES baseline B-B et B-T
**As** développeur Rust **I want** signer un document XML en XAdES, horodaté **so that** DSS le déclare `XAdES-BASELINE-T`.

- **Complexity**: 3
- **Depends on**: s24-xmldsig
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-xades/`

### Acceptance criteria
- [ ] Un document XML signé en XAdES (`SignedProperties` avec `SigningTime` et `SigningCertificateV2`) est déclaré `TOTAL_PASSED` au niveau `XAdES-BASELINE-B` par DSS, puis `-T` avec un `SignatureTimeStamp`.
- [ ] La validation de Nacre rend le même niveau et la même indication que DSS, chaîne (s16) et révocation (s17) comprises.
- [ ] Une `SignedProperties` non référencée par la signature, ou modifiée, fait échouer la validation.

### Notes for the agent
Réutiliser `nacre-xml`, `nacre-tsp` et l'API publique de `nacre-validate`.

## s26-xades-blt-blta — Monter une signature XAdES aux niveaux B-LT et B-LTA
**As** développeur Rust **I want** qu'une signature XAdES embarque ses données de validation et un horodatage d'archive **so that** DSS la déclare `XAdES-BASELINE-LTA`.

- **Complexity**: 4
- **Depends on**: s25-xades-bb-bt
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-xades/`

### Acceptance criteria
- [ ] `CertificateValues` et `RevocationValues` (signataire et TSA) montent la signature à `XAdES-BASELINE-LT` dans DSS.
- [ ] Un `ArchiveTimeStamp` monte la signature à `XAdES-BASELINE-LTA` dans DSS ; un second s'ajoute plus tard sans casser le premier.
- [ ] La validation de Nacre rend le même niveau que DSS.

### Notes for the agent
Risque principal : la canonicalisation de l'entrée de l'`ArchiveTimeStamp` (EN 319 132-1), qui couvre des éléments ajoutés après la signature ; confronter à DSS à chaque étape.

## s27-asic-xades — Conteneurs ASiC avec signature XAdES
**As** développeur Rust **I want** les conteneurs ASiC-S et ASiC-E signés en XAdES **so that** les deux variantes d'ASiC reconnues par DSS soient couvertes.

- **Complexity**: 2
- **Depends on**: s23-asic-cades, s26-xades-blt-blta
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-asic/`

### Acceptance criteria
- [ ] Un ASiC-S et un ASiC-E signés en XAdES (`META-INF/signatures.xml`) sont déclarés `TOTAL_PASSED` par DSS au niveau XAdES demandé.
- [ ] La validation de Nacre rend le même niveau que DSS ; un fichier modifié dans le conteneur la fait échouer.

### Notes for the agent
Même lecture de conteneur et mêmes protections que s23.

## s28-jws — Signer et vérifier en JWS
**As** développeur Rust **I want** signer et vérifier des données en JWS, sérialisations compacte et JSON **so that** JAdES et les API web reposent sur une implémentation JWS de Nacre.

- **Complexity**: 2
- **Depends on**: s20-nacre-sig-milestone
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-jose/`, `docs/security/attacks/jose.md`

### Acceptance criteria
- [ ] Les vecteurs de la RFC 7515 (annexe A) et de la RFC 7520 donnent, en ES256, RS256 et EdDSA, la sortie attendue ; un JWS de `josekit` est vérifié par Nacre et l'inverse.
- [ ] `alg: none`, un `alg` différent de celui attendu par l'appelant, une clé symétrique présentée comme publique (confusion HS/RS) et un en-tête `crit` inconnu sont tous rejetés, et listés dans `docs/security/attacks/jose.md`.
- [ ] La charge utile détachée (RFC 7797, `b64: false`) est prise en charge.
- [ ] Une entrée hostile rend une erreur, jamais un panic ; une cible de fuzzing existe.

### Notes for the agent
Famille écrite pour l'exercice : elle reste marquée expérimentale dans sa documentation jusqu'à être fuzzée et confrontée à `josekit` (brief, Security & abuse). Le JSON lui-même passe par `serde_json`.

## s29-jades-bb-bt — Signer et valider en JAdES baseline B-B et B-T
**As** développeur Rust **I want** signer des données en JAdES, horodatées **so that** DSS les déclare `JAdES-BASELINE-T`.

- **Complexity**: 3
- **Depends on**: s28-jws
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-jades/`

### Acceptance criteria
- [ ] Une signature JAdES (en-têtes `sigT`, `x5t#S256` ou `sigX5ts`, `x5c`) est déclarée `TOTAL_PASSED` au niveau `JAdES-BASELINE-B` par DSS, puis `-T` avec un `sigTst` dans l'en-tête non protégé `etsiU`.
- [ ] La validation de Nacre rend le même niveau et la même indication que DSS.
- [ ] Un en-tête protégé modifié fait échouer la validation.

### Notes for the agent
ETSI TS 119 182-1. Réutiliser `nacre-jose`, `nacre-tsp` et l'API publique de `nacre-validate`.

## s30-jades-blt-blta — Monter une signature JAdES aux niveaux B-LT et B-LTA
**As** développeur Rust **I want** qu'une signature JAdES embarque ses données de validation et un horodatage d'archive **so that** DSS la déclare `JAdES-BASELINE-LTA`.

- **Complexity**: 4
- **Depends on**: s29-jades-bb-bt
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-jades/`

### Acceptance criteria
- [ ] `xVals` et `rVals` montent la signature à `JAdES-BASELINE-LT` dans DSS.
- [ ] Un `arcTst` monte la signature à `JAdES-BASELINE-LTA` dans DSS ; un second s'ajoute plus tard sans casser le premier.
- [ ] La validation de Nacre rend le même niveau que DSS.

### Notes for the agent
Risque principal : la canonicalisation de l'entrée de `arcTst` (JSON de `etsiU`, TS 119 182-1 §5.3.6), peu documentée ; confronter à DSS.

## s31-cose — Signer et vérifier en COSE
**As** développeur Rust **I want** signer et vérifier des messages `COSE_Sign1` et `COSE_Sign` **so that** les usages CBOR (mdoc, WebAuthn, appareils) aient une signature Nacre.

- **Complexity**: 3
- **Depends on**: s20-nacre-sig-milestone
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-cose/`, `docs/security/attacks/cose.md`

### Acceptance criteria
- [ ] Les exemples de signature de la RFC 9052 (et du dépôt `cose-wg/Examples`) sont produits et vérifiés à l'octet près, en ES256 et EdDSA.
- [ ] Un message produit par `coset` est vérifié par Nacre et l'inverse (confrontation différentielle).
- [ ] Un algorithme non attendu, un en-tête protégé modifié ou un encodage CBOR non déterministe là où il est exigé est rejeté ; les attaques connues sont listées dans `docs/security/attacks/cose.md`.
- [ ] Une entrée hostile rend une erreur, jamais un panic ; une cible de fuzzing existe.

### Notes for the agent
Famille écrite pour l'exercice, marquée expérimentale jusqu'à être fuzzée et confrontée à `coset`. CBOR est l'encodage (comme DER pour CMS) : il passe par `ciborium`. Pas de profil AdES pour COSE : aucun niveau, aucun DSS.

## s32-openpgp — Signer et vérifier des signatures OpenPGP détachées
**As** développeur Rust **I want** produire et vérifier des signatures OpenPGP détachées **so that** commits, paquets et fichiers signés en OpenPGP passent par la même bibliothèque.

- **Complexity**: 4
- **Depends on**: s20-nacre-sig-milestone
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-openpgp/`, `docs/security/attacks/openpgp.md`

### Acceptance criteria
- [ ] Une clé publique OpenPGP (RFC 9580, v4 et v6) est lue ; une signature détachée binaire ou armurée d'un fichier est vérifiée.
- [ ] Nacre produit une signature détachée v4 et v6 (Ed25519, ECDSA P-256, RSA) que `gpg --verify` et `rpgp` acceptent.
- [ ] Des signatures produites par `gpg` et `rpgp` sont vérifiées par Nacre (confrontation différentielle).
- [ ] Une sous-clé sans liaison valide, une signature d'une clé révoquée ou expirée, un algorithme faible (SHA-1, DSA) ou un paquet de type inconnu critique est rejeté ; les attaques connues sont listées dans `docs/security/attacks/openpgp.md`.
- [ ] Une entrée hostile rend une erreur, jamais un panic ; une cible de fuzzing existe.

### Notes for the agent
Risque principal : le parseur de paquets OpenPGP, surface d'attaque connue (longueurs partielles, paquets imbriqués, compression). Famille écrite pour l'exercice, marquée expérimentale jusqu'à être fuzzée et confrontée à `rpgp`. Hors périmètre : chiffrement, toile de confiance, serveurs de clés. OpenPGP n'utilise pas X.509 : rien ne passe par `nacre-validate`.

## s33-sshsig — Signer et vérifier au format SSH (sshsig)
**As** développeur Rust **I want** signer et vérifier des données au format `sshsig` **so that** les signatures de commits git et de fichiers par clé SSH passent par Nacre.

- **Complexity**: 2
- **Depends on**: s20-nacre-sig-milestone
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-ssh/`, `docs/security/attacks/ssh.md`

### Acceptance criteria
- [ ] Une signature `sshsig` d'Ed25519 ou d'ECDSA P-256, produite par Nacre, est vérifiée par `ssh-keygen -Y verify` ; une signature d'`ssh-keygen -Y sign` est vérifiée par Nacre.
- [ ] Des signatures produites par `ssh-key` sont vérifiées par Nacre et l'inverse.
- [ ] Un espace de noms (`namespace`) différent de celui attendu par l'appelant est rejeté ; les attaques connues sont listées.
- [ ] Une entrée hostile rend une erreur, jamais un panic ; une cible de fuzzing existe.

### Notes for the agent
Famille écrite pour l'exercice, marquée expérimentale jusqu'à être fuzzée et confrontée à `ssh-key`. Le signataire peut être un `Signer` PKCS#11 (s13) pour une clé ECDSA P-256.

## s34-minisign — Signer et vérifier au format minisign
**As** développeur Rust **I want** signer et vérifier des fichiers au format minisign **so that** la vérification d'un outil téléchargé passe par Nacre.

- **Complexity**: 2
- **Depends on**: s20-nacre-sig-milestone
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-minisign/`, `docs/security/attacks/minisign.md`

### Acceptance criteria
- [ ] Une signature minisign (Ed25519, préhachée BLAKE2b ou non) produite par Nacre est vérifiée par l'outil `minisign` et par la crate `minisign-verify` ; une signature de l'outil est vérifiée par Nacre.
- [ ] Le commentaire de confiance est couvert par la signature globale : le modifier fait échouer la vérification.
- [ ] Un identifiant de clé différent, ou une signature non préhachée quand l'appelant exige le préhachage, est rejeté ; les attaques connues sont listées.
- [ ] Une entrée hostile rend une erreur, jamais un panic ; une cible de fuzzing existe.

### Notes for the agent
Famille écrite pour l'exercice, marquée expérimentale jusqu'à être fuzzée et confrontée à `minisign`. Le format de clé secrète chiffrée de minisign est hors périmètre : la clé vient d'un `Signer`.

## s35-csc-signer — Signer à distance par l'API Cloud Signature Consortium
**As** développeur Rust **I want** un `Signer` qui signe par un service de signature à distance compatible CSC **so that** une clé gardée par un prestataire serve toutes les familles de Nacre.

- **Complexity**: 4
- **Depends on**: s20-nacre-sig-milestone
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-csc/`

### Acceptance criteria
- [ ] Le `Signer` CSC (API v2) liste les identifiants de certificat, autorise une signature (`credentials/authorize`) et signe une empreinte (`signatures/signHash`) ; contre un serveur CSC simulé, la signature est vérifiée.
- [ ] Un PDF signé par ce `Signer` contre un serveur simulé adossé à la PKI de s02 est déclaré `PAdES-BASELINE-B` par DSS.
- [ ] Un jeton d'accès expiré, une autorisation refusée ou une réponse mal formée rend une erreur distincte, sans panic ; aucun secret n'apparaît dans les messages ni les journaux.
- [ ] Le transport passe par la feature `http` ; sans elle, l'appelant fournit le sien.

### Notes for the agent
Risque principal : les prestataires CSC réels divergent (flux OAuth, SCAL1 ou SCAL2, OTP). Cette story s'arrête au serveur simulé ; un essai contre un prestataire réel n'est fait que si un compte de test existe, et il est consigné.

## s36-trust-lists — Charger les listes de confiance de l'UE comme ancres
**As** développeur Rust **I want** charger la liste des listes de confiance de l'UE (LOTL) et les listes nationales comme ancres de validation **so that** une signature émise par un prestataire qualifié se valide sans déclarer sa racine à la main.

- **Complexity**: 4
- **Depends on**: s26-xades-blt-blta
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-trust/`

### Acceptance criteria
- [ ] La LOTL et une liste nationale (ETSI TS 119 612) sont lues, et leur signature XAdES vérifiée avec les certificats publiés au Journal officiel de l'UE pour la LOTL.
- [ ] Les services d'un statut donné (qualifié, accordé, retiré) et d'un type donné (autorité de certification, TSA) deviennent des ancres utilisables par `nacre-validate`, chacune avec sa période de validité.
- [ ] Une liste à signature invalide, expirée (`NextUpdate` passé) ou signée par un certificat absent de la LOTL est refusée, avec une erreur qui le dit.
- [ ] Les tests tournent sur des copies enregistrées des listes ; la CI n'appelle jamais le réseau.

### Notes for the agent
Risque principal : la chaîne de confiance des listes elles-mêmes (certificats de signature de la LOTL publiés au JOUE, rotation) et le volume des listes. Les ancres restent un choix de l'appelant : sans demande explicite, la validation n'utilise pas les listes (brief, constat 5).

## s37-nacre-sig-all-families — Exposer toutes les familles dans la façade nacre-sig
**As** développeur Rust **I want** activer n'importe quelle famille depuis `nacre-sig` par sa feature **so that** une seule dépendance regroupe toutes les signatures, sans compiler ce que je n'active pas.

- **Complexity**: 2
- **Depends on**: s27-asic-xades, s30-jades-blt-blta, s31-cose, s32-openpgp, s33-sshsig, s34-minisign, s35-csc-signer, s36-trust-lists
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-sig/`, `README.md`, `CHANGELOG.md`

### Acceptance criteria
- [ ] `nacre-sig` expose les features `cades`, `asic`, `xades`, `jades`, `cose`, `openpgp`, `ssh`, `minisign`, `csc` et `trust-lists`, aucune par défaut.
- [ ] Pour chaque feature activée seule, `cargo tree` ne montre aucune crate d'une autre famille ; un test de la CI le vérifie pour chacune.
- [ ] Le `README.md` liste chaque famille et son état : stable, ou expérimentale tant qu'elle n'est pas fuzzée et confrontée à sa crate de référence.
- [ ] `cargo publish --dry-run -p nacre-sig` passe ; `CHANGELOG.md` décrit la version.

### Notes for the agent
L'outil en ligne de commande et les liaisons pour d'autres langages restent en V2 (brief, non-goals) : pas de binaire ici.

## s38-error-kind — Une catégorie d'erreur grossière à montrer aux tiers
**As** développeur d'une application qui sert des tiers **I want** une catégorie d'erreur grossière pour chaque erreur de Nacre **so that** je ne montre à l'extérieur rien qui décrive la cause, tout en gardant le détail pour moi.

- **Complexity**: 2
- **Depends on**: s01-workspace-contract, s03-cms-signed-data, s04-pdf-read
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-core/`, `crates/nacre-cms/src/error.rs`, `crates/nacre-pdf/src/error.rs`, `crates/nacre-pdf/Cargo.toml`

### Acceptance criteria
- [ ] `nacre-core` expose `ErrorKind` (`InvalidInput`, `InvalidSignature`, `Indeterminate`, `Signer`, `Unavailable`, `#[non_exhaustive]`) et `nacre_core::Error::kind()`.
- [ ] `nacre-cms` et `nacre-pdf` exposent `kind()` sur leur `Error` ; chaque variante a sa catégorie, ce qu'un test vérifie sur toutes les variantes.
- [ ] Le `Display` de `ErrorKind` est un texte fixe qui ne dépend jamais de l'entrée.
- [ ] Aucun message d'erreur ne contient de secret : un test vérifie que le secret du signataire de test de `nacre-core` (octets bruts, hexadécimal ou liste décimale) n'apparaît dans aucun `Display`, `Debug` ou `source` de ses erreurs. Le PIN est vérifié par s13.

### Notes for the agent
Story contrat (ADR-0012) : `nacre-core` est gelé après s01 et ne change que par une story contrat ; s06 à s37 suivent la convention « chaque `Error` expose `kind()` ». Les sous-indications EN 319 102-1 de `validate` sont des résultats, pas des erreurs : elles ne passent pas par `ErrorKind`. Ajouter une variante à `ErrorKind` est un changement de contrat, d'où `#[non_exhaustive]`.

## s39-error-kind-from-sources — Le kind() d'une erreur d'horodatage ou de révocation dit sa vraie catégorie
**As** développeur d'une application qui sert des tiers **I want** que le `kind()` d'une erreur de TSA ou de révocation dise la vraie catégorie **so that** je ne relance pas une attaque comme une panne.

- **Complexity**: 2
- **Depends on**: s07-tsp-client, s09-revocation-crl, s38-error-kind
- **Surface**: `endpoint`
- **Owns**: `crates/nacre-core/`, `crates/nacre-tsp/src/`, `crates/nacre-revocation/src/`

### Acceptance criteria
- [ ] `nacre_core::Error::Timestamp` et `nacre_core::Error::Revocation` portent un `ErrorKind` fixé par la source, `Unavailable` par défaut, et `kind()` le rend.
- [ ] `HttpTsa` : un jeton forgé ou rejoué rend `InvalidSignature` ; une empreinte de mauvaise longueur rend `InvalidInput` ; une TSA injoignable rend `Unavailable`.
- [ ] `HttpCrlSource` : une CRL invalide rend `InvalidSignature` ou `InvalidInput` selon la cause ; une adresse refusée (SSRF) rend `InvalidInput` ; un serveur injoignable rend `Unavailable`.
- [ ] Un test par cas, sur un serveur local.

### Notes for the agent
Story contrat (ADR-0016, qui précise l'ADR-0012) : `nacre-core` est gelé et ne change que par une story contrat. Ne pas deviner le kind par downcast dans `nacre-core`. Jamais de TSA publique en test.
