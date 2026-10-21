---
product: Nacre
status: approved
date: 2026-10-21
---
# Brief — Nacre

`/po-brief` fills this file theme by theme, following the `interrogation` skill. `status` moves from `interviewing` to `approved` once, at `/po-brief`'s commit, when every exit criterion holds and every theme was approved on its own question; the brief is never shown again for reading.

**One-liner.** Nacre (crate `nacre-sig`) est une bibliothèque Rust libre, sous MIT ou Apache-2.0, qui regroupe toutes les familles de signature électronique (CMS et ses profils européens PAdES, CAdES, ASiC ; XML-DSig et XAdES ; JWS et JAdES ; COSE ; OpenPGP ; SSH ; minisign) : elle signe, y compris avec une clé matérielle comme une YubiKey, et elle valide ; chaque famille s'active à la demande, et chaque niveau est prouvé conforme face à DSS, l'outil de référence de la Commission européenne. Son premier usage : signer en PAdES jusqu'à B-LTA les décisions du registre de Patelle.

## Problem & evidence
Le seul cas concret est Patelle. Sa story s01 (21/10/2026) a montré qu'`ades-rs` 0.2 produit du `PAdES-BES` et non du B-T : il ajoute l'attribut `signing-time`, interdit par ETSI EN 319 142-1, et n'a ni dictionnaire `/DSS` ni B-LTA. Aucune autre bibliothèque Rust n'est utilisable : `pdf_signer` est sous GPL-3.0 et ne signe qu'à partir d'un fichier PKCS#12, `pdfluent` est commercial, `oxidize-pdf` exclut PAdES. Coût : l'échéance du 30/11/2026 de Patelle glisse jusqu'au premier jalon de Nacre.

Le moteur est le besoin propre d'ATOLL LABS : une seule bibliothèque qui regroupe toutes les familles de signature. Utilisateurs et contributeurs extérieurs sont bienvenus, sans être un objectif.

Aucune demande extérieure n'est prouvée : l'offre commerciale reste une hypothèse et n'oriente pas le périmètre.

## Consumer & job
- **Programme : `patelle-lib`**, premier client. Quand le président signe une décision, le PDF entre, la YubiKey signe par PKCS#11, une TSA horodate (RFC 3161) et le PDF ressort au niveau demandé, jusqu'à B-LTA. Quand on vérifie le registre, Nacre valide la signature et rend le niveau AdES atteint.
- **Développeur** : le président d'ATOLL LABS d'abord, puis tout développeur Rust qui ajoute Nacre à son projet (autres projets d'atoll, contributeurs bienvenus). Il n'active que les features dont il a besoin et appelle une API commune à toutes les familles : signataire, certificat, horodatage, validation.
- **Outil en ligne de commande** : un binaire de debug pour développeurs, qui inspecte une signature, affiche le niveau atteint, signe ou valide à la main. Reporté en V2, sauf s'il devient nécessaire avant (pour déboguer Patelle, par exemple). La plateforme `cli` reste déclarée dans `AGENTS.local.md` pour ce moment-là.

## Status quo & incumbents
**En Rust, aujourd'hui** :
- RustCrypto (`cms`, `x509-cert`, `der`) fournit l'enveloppe CMS, sans aucun profil AdES ;
- OpenPGP a `rpgp` (MIT/Apache-2.0) et Sequoia (LGPL) ; `sshsig` a `ssh-key` ; minisign a `minisign` et `minisign-verify` ; COSE a `coset` ; JWS a plusieurs crates.

Rien ne fournit PAdES ou CAdES baseline conformes, l'horodatage RFC 3161 intégré, la validation AdES (niveau atteint) ni un signataire PKCS#11 commun.

**Hors Rust** : EU DSS (Java), la référence, utilisée comme juge de conformité ; pyHanko (Python).

**Décision** : Nacre écrit tous les formats de zéro, y compris ceux que l'écosystème couvre déjà (OpenPGP, `sshsig`, minisign, JWS, COSE). Le motif est assumé : l'exercice, pas un manque. Les primitives (SHA-2, ECDSA, RSA, EdDSA), l'ASN.1/DER et X.509 restent à RustCrypto et ne sont jamais réécrits.

Revenir à une façade sur `rpgp`, `ssh-key`, `minisign` et `coset` reste la simplification possible plus tard ; elle figure au tableau des alternatives.

## Wedge & non-goals
**Premier jalon : les features `cms`, `pades`, `tsp`, `validate` et `pkcs11`.** Signer un PDF en PAdES baseline de B-B à B-LTA avec une YubiKey par PKCS#11, un horodatage RFC 3161 et les données de révocation dans le dictionnaire `/DSS`, puis le valider avec Nacre, qui rend le niveau exact atteint. Patelle l'utilise à chaque décision.

La validation reste dans le jalon malgré son poids : les normes et les implémentations de référence (DSS, pyHanko) sont publiques, le travail est de transcription. Le risque qu'elle ne passe que les cas nominaux est suivi sous « Open risks & spikes ».

Après le jalon : `cades`, `asic`, `xades`, `jades`, `cose`, `openpgp`, `ssh`, `minisign`, `csc`, `trust-lists`.

Non-goals :
- réécrire les primitives, l'ASN.1/DER ou X.509 : ils restent à RustCrypto ;
- la signature qualifiée (QES) et toute certification : Nacre produit des signatures avancées, elle ne devient ni prestataire de confiance ni produit certifié ;
- être un service : pas de serveur, pas d'API HTTP, pas de TSA ni d'autorité de certification ; Nacre est client d'une TSA, jamais une TSA ;
- les usages bâtis sur ces formats (Sigstore, C2PA, S/MIME, signature de code) : Nacre fournit les formats, pas les écosystèmes ;
- les liaisons pour d'autres langages (C, Python, WASM) et l'outil en ligne de commande : V2 ;
- réparer un PDF mal formé : Nacre le refuse avec une erreur claire, car signer un PDF réparé, c'est signer autre chose que ce que l'auteur a vu.

## Success metric
**Au dimanche 25/10/2026**, une campagne scriptée et rejouable en CI donne :
1. DSS (exécuté en local, version figée) rend `TOTAL_PASSED` aux niveaux `PAdES-BASELINE-B`, `-T`, `-LT` et `-LTA` pour un PDF signé avec la YubiKey ;
2. sur le même corpus, signatures valides et invalides, le verdict de `validate` (indication et niveau) est identique à celui de DSS dans 100 % des cas ;
3. Patelle bascule sur Nacre et sa propre campagne de conformité passe.

**Échec** : un seul écart de niveau entre Nacre et DSS, ou un contournement que Patelle doit garder.

**Mesure** : les rapports XML de DSS sont conservés comme preuve de chaque campagne.

**Repli si la date passe** : la signature (`cms`, `pades`, `tsp`, `pkcs11`) sort seule, Patelle vérifie par DSS, et `validate` suit sans date imposée. La date a été fixée contre l'avis du brief, qui la juge intenable pour `validate`.

## Premises
1. Le besoin est celui d'ATOLL LABS, Patelle d'abord ; aucune demande extérieure ne conditionne le périmètre.
2. Au 21/10/2026, aucune bibliothèque Rust ne fournit PAdES baseline conforme, sous licence permissive et utilisable avec une clé matérielle.
3. Les formats sont écrits de zéro, pour l'exercice ; primitives, ASN.1/DER et X.509 restent à RustCrypto.
4. DSS, en local et à version figée, est le juge de conformité : une feature ne sort qu'avec un test qui vérifie le niveau exact rendu, jamais la seule indication.
5. La validation est une transcription de normes et d'implémentations publiques : des agents la livrent dans le premier jalon.
6. Chaque famille est une cargo feature indépendante : activer seulement `pades` ne compile rien des autres familles.
7. Le corpus de conformité confronté à DSS, valide et invalide, est un livrable publié et maintenu comme le code ; c'est lui qui garde sa valeur dans deux ans.
8. C'est le moment : Patelle est bloqué depuis s01, et le travail de s01 (traits `Signer` et `TimestampAuthority`, tests SoftHSM, conteneur DSS) se réutilise.

## Gap map
Status is one of `answered`, `defaulted`, `open risk`, `N/A`. A dimension marked ★ in the skill never stays blank.

| Dimension | Status | Evidence, default or risk |
| --- | --- | --- |
| ★ Problem & evidence | answered | Patelle s01 (21/10/2026) ; besoin propre d'ATOLL LABS, voir « Problem & evidence » |
| ★ Consumer & job | answered | `patelle-lib`, développeurs Rust ; outil CLI en V2 |
| ★ Wedge & non-goals | answered | premier jalon `cms`, `pades`, `tsp`, `validate`, `pkcs11` ; cinq non-goals |
| ★ Success metrics | answered | campagne DSS au 25/10/2026, rapports XML conservés |
| ★ Incumbents & alternatives | answered | voir « Status quo & incumbents » |
| Product & distribution | answered | crate `nacre-sig` (lib `nacre`, libre au 21/10/2026), MIT OR Apache-2.0, crates.io et GitHub `atoll-labs-io/nacre`, gratuit ; l'offre commerciale reste une hypothèse |
| ★ Domain model | defaulted | document PDF (révisions incrémentales, aucun octet existant modifié), `SignedData`, signataire, chaîne X.509, jeton d'horodatage, données de révocation (`/DSS`, VRI), rapport de validation (indication, sous-indication, niveau). Nacre fournit l'extension de l'horodatage d'archive, l'appelant décide quand la lancer. PDF jusqu'à 50 Mo. Le lecteur PDF est écrit par Nacre, au minimum que PAdES exige, flux xref et flux d'objets compris |
| ★ Interface contract | defaulted | API Rust synchrone, réseau (TSA, CRL, OCSP) derrière des traits injectés, implémentation par défaut sous la feature `http`. Semver 0.x jusqu'à la stabilisation de Patelle, puis 1.0 ; MSRV : stable moins deux versions ; CHANGELOG pour chaque rupture |
| Quality attributes | defaulted | signer un PDF de 10 Mo en moins de 1 s, hors réseau et hors YubiKey ; valider en moins de 2 s hors réseau |
| ★ Security & abuse | defaulted | chaque parseur (PDF, CMS, TSP, CRL, OCSP) traite une entrée hostile : aucun panic, récursion et taille bornées, fuzzé en CI avant la sortie de sa feature. `forbid(unsafe_code)` hors liaison PKCS#11 (`cryptoki`). PIN effacé de la mémoire, jamais journalisé ; la clé ne quitte jamais le jeton. Corpus en documents fictifs uniquement, DSS seulement en local. Les familles écrites pour l'exercice restent marquées expérimentales jusqu'à être fuzzées |
| Operations | defaulted | CI GitHub Actions : tests, clippy, conteneur DSS, SoftHSM, TSA locale. Tests YubiKey à la main, consignés. Publication sur crates.io par un humain |
| ★ Evaluation | answered | corpus différentiel face à DSS, valide et invalide ; familles écrites pour l'exercice confrontées à `rpgp`, `ssh-key`, `minisign` et `coset` |
| Technical unknowns | open risk | voir « Open risks & spikes » |

## Pre-mortem findings
Outcome is one of `accepted`, `refuted`, `spike`.

| Finding | Outcome | Reasoning |
| --- | --- | --- |
| La date du 25/10/2026 est intenable : le repli devient le plan réel et `validate`, « sans date imposée », ne sort jamais (« Success metric ») | refuted | Ces technologies existent déjà ailleurs (DSS, pyHanko, RustCrypto) ; des agents les transcrivent vite |
| Le périmètre est un exercice : réécrire OpenPGP, `sshsig`, minisign, COSE et JWS sans besoin disperse un développeur seul, et rien ne justifie l'effort une fois Patelle débloqué (« Status quo & incumbents ») | refuted | « C'est pour moi avant tout » : l'exercice est le but, la dispersion fait partie du choix |
| Le lecteur PDF minimal cède face aux vrais PDF : xref hybrides, révisions corrompues, PDF/A, formulaires, PDF déjà signés (« Domain model ») | accepted | Le corpus du spike PDF couvre ces cas ; non-goal : Nacre refuse un PDF qu'elle ne lit pas proprement, avec une erreur claire, et ne le répare jamais |
| Un faux « valide » détruit la confiance : la ligne Sécurité ignore les attaques logiques contre les PDF signés, que le fuzzing ne trouve pas (« Security & abuse ») | accepted | Toutes les failles connues sont gérées : liste versionnée des attaques publiées par format (PAdES : USF, ISA, SWA, shadow attacks hide/replace/hide-and-replace, attaques EAA et SSA sur les PDF certifiés ; CMS et X.509 : confusion d'algorithme, attributs signés absents ou dupliqués, chaîne contournée), un cas invalide par attaque dans le corpus, une feature ne sort que si toutes sont rejetées. `validate` signale et qualifie chaque révision postérieure à la dernière signature |
| La campagne tourne en rond : un corpus produit par Nacre et sa PKI de test partage ses angles morts, et les ancres de confiance de `validate` sont floues sans `trust-lists` (« Success metric », « Open risks & spikes ») | accepted | Le corpus inclut des signatures produites par DSS, pyHanko, Adobe Acrobat et des PDF signés publics ; l'ancre de confiance est fournie explicitement par l'appelant, et sans ancre `validate` rend « indéterminé », jamais « valide » |
| La prémisse 5 est fausse : EN 319 102-1 (sous-indications, révocation dans le temps, POE, horodatages imbriqués) demande du jugement, pas une transcription (« Premises ») | spike | Avant la story `validate`, confronter le rapport détaillé de DSS aux blocs de EN 319 102-1 sur une dizaine de cas limites et trancher, là où ils divergent, entre la norme et DSS |
| Aucune demande, un seul mainteneur, aucun modèle économique : sur la PKI et la conformité, le facteur bus est fatal (« Problem & evidence ») | accepted | Facteur bus nommé en risque ouvert ; le README avertit que `validate` n'a pas été relu par un tiers et ne doit pas servir de seule preuve hors d'atoll avant un audit externe |

Questions que le brief évitait, selon le pré-mortem :
- débloquer Patelle tout de suite par DSS ou pyHanko en sidecar, ou en corrigeant `ades-rs`, plutôt qu'attendre une réécriture : traité au tableau des alternatives ;
- Nacre, produit pour Patelle ou projet d'apprentissage, et lequel gagne en cas de conflit de calendrier : les deux, sans arbitrage (constats 1 et 2 réfutés) ;
- qui répond de la justesse du validateur dans deux ans : constat 7.

## Alternatives considered

| Approach | Effort | Risk | What it gives up |
| --- | --- | --- | --- |
| **A. Nacre complète (retenue)** : tous les formats écrits de zéro, premier jalon PAdES, chaque famille derrière sa feature | le plus lourd : dix familles | dispersion d'un développeur seul, date du premier jalon | rien du but ; tout le temps. Retenue parce que l'exercice est le but (prémisses 1 et 3) |
| B. Nacre façade : Nacre écrit AdES, TSP, `validate`, PKCS#11 et le PDF ; OpenPGP, SSH, minisign, COSE et JWS délèguent à `rpgp`, `ssh-key`, `minisign`, `coset` | environ la moitié de A | dépendances externes | l'exercice sur cinq familles. Rejetée parce que l'exercice est le but ; elle reste la simplification possible plus tard. C'était la recommandation du brief |
| C. Sidecar DSS pour Patelle : Patelle signe et valide par DSS en local, sans Nacre | quelques jours, la moins chère | Java dans la chaîne, contre l'ADR-0003 de Patelle ; PKCS#11 du côté de DSS | toute la bibliothèque Rust. Rejetée : elle laisse le manque de l'écosystème Rust et ne sert que Patelle |
| D. Corriger `ades-rs` en amont : retirer `signing-time`, ajouter `/DSS` et B-LTA | moyen | dépend d'un mainteneur externe ; un PAdES bâti sur des habitudes CAdES, testé sur la seule indication | la maîtrise et l'API commune. Rejetée : `/DSS`, B-LTA et la validation seraient à écrire de toute façon, sur une base qui n'est pas à nous |

## Open risks & spikes
- **La validation ne passe que les cas nominaux** (certificat révoqué entre deux horodatages, CRL périmée, attribut interdit, chaîne incomplète) — retiré par une confrontation différentielle à DSS sur un corpus qui contient des signatures invalides, exigée avant que `validate` sorte.
- **Lecteur PDF minimal face aux vrais PDF** (flux xref, flux d'objets, xref hybrides, révisions corrompues, PDF/A, formulaires, PDF déjà signés) — spike sur un corpus de PDF produits par Word, LibreOffice, l'impression de navigateurs et des tiers, avant la story `pades`.
- **YubiKey PIV par PKCS#11 en ECDSA P-256** (ykcs11 ou OpenSC, signature d'une empreinte) — spike sur la clé réelle, avant la story `pkcs11`.
- **Validation : norme ou DSS sur les cas limites** — spike avant la story `validate` (constat 6 du pré-mortem).
- **Facteur bus** : un seul mainteneur sur un validateur de signatures — avertissement dans le README tant qu'aucun audit externe n'a relu `validate`.
- **PKI de test** (racine, CRL, répondeur OCSP) pour couvrir la révocation dans la campagne — construite dans la première story qui touche B-LT.
