# Nacre

Bibliothèque Rust libre de signatures électroniques avancées : l'enveloppe CMS et ses profils européens (PAdES, CAdES, puis ASiC, XAdES, JAdES, COSE), avec leur validation. Décidée le 22/10/2026, pendant la story s01 de Patelle.

Nom : la nacre se construit couche après couche, comme une signature monte de B-B à B-T, B-LT puis B-LTA par révisions successives.

## Pourquoi

- En octobre 2026, aucune bibliothèque Rust ne produit du PAdES baseline conforme, maintenue et utilisable avec une clé matérielle :
  - `ades-rs` 0.2 (lfern/eidas-rs) recopie les attributs CAdES dans PAdES (`signing-time` interdit par ETSI EN 319 142-1), range le « B-LT » dans le CMS au lieu du dictionnaire `/DSS`, n'a pas de B-LTA ; ses tests ne vérifient que l'indication `TOTAL_PASSED` de DSS, jamais le niveau rendu ;
  - `pdf_signer` 0.3 respecte le profil baseline jusqu'à B-LTA, mais il est sous GPL-3.0 et ne signe qu'avec un fichier PKCS#12 (clé exportable) ;
  - `pdfluent` est commercial ; `oxidize-pdf` exclut PAdES ; `pdf_signing` est abandonné.
- Patelle (`../patelle/`) en a besoin pour son registre : PAdES B-B à B-LTA, signature par PKCS#11 (YubiKey), horodatage RFC 3161, validation.
- Stratégie d'atoll : des outils libres et souverains, puis une offre commerciale.

## Points de départ pour le brief

- **Couches** (carte complète : artefact « Atlas des signatures ») : primitives cryptographiques et encodages ASN.1/DER, X.509 viennent de RustCrypto et ne sont jamais réécrits ; Nacre écrit le modèle CMS SignedData, les profils AdES, l'horodatage, la validation (chemin X.509, CRL, OCSP, niveau AdES atteint) et les signataires (PKCS#11, puis signature à distance CSC).
- **Fonctions activables une à une** (cargo features) : `cms`, `pades`, `tsp`, `validate`, `pkcs11` d'abord ; puis `cades`, `asic`, `xades`, `jades`, `cose`, `csc`, `trust-lists`.
- **Hors périmètre** : OpenPGP (Sequoia), Sigstore (sigstore-rs), C2PA (c2pa-rs), signatures SSH.
- **Preuve de conformité** : chaque fonction ne sort qu'avec un test qui confronte sa sortie à DSS (Commission européenne, local, version figée) et vérifie le **niveau exact** rendu, jamais la seule indication.
- **Licence** : MIT OR Apache-2.0, l'usage de l'écosystème Rust.
- **Nom du crate** : `nacre` est déjà pris sur crates.io (un noyau de CAO) ; `nacre-sig` est libre (relevé le 22/10/2026). À trancher au brief.
- **Premier client** : Patelle, dont l'échéance du 30/11/2026 glisse pour attendre Nacre (décision du 22/10/2026).
