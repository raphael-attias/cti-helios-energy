# Analyse des 40 entrées IoC

Date : 2026-10-06. Source : `fourniture/02_indicateurs_40.csv` (40 lignes, identique au JSON), inventaire `02-Artefacts/Inventaire-IoC.csv`. Format de chaque conclusion : observation, preuve, interprétation, confiance, limite. Vocabulaire : OBSERVÉ (présent dans un journal ou une alerte), CORROBORÉ, DÉCLARÉ (affirmé par le dossier sans artefact d'observation), HYPOTHÈSE, INCONNU, NON VÉRIFIABLE.

## 1. Synthèse chiffrée

| Mesure | Valeur |
|---|---|
| Entrées | 40 (10 IPv4, 12 hashes fichiers dont 3 jeux MD5/SHA-1/SHA-256, 6 domaines, 4 URL, 3 empreintes de certificat, 5 « host ») |
| Doublons, valeurs invalides | 0, 0 |
| Entrées OBSERVÉES dans un journal brut | 9 : IOC-013, 016, 020, 024, 025, 029, 036, 037, 040 |
| Entrées CORROBORÉES en partie | 3 : IOC-004 à 006 (taille de BIN-002 = taille de la réponse Squid ; le hash n'est pas recalculable) |
| Entrées vues seulement dans le détail d'une alerte | 1 : IOC-014 |
| Entrées DÉCLARÉES sans artefact d'observation | 25 |
| Entrées NON VÉRIFIABLES (source externe absente) | 2 : IOC-028, IOC-035 |
| Contrôle de somme | 9 + 3 + 1 + 25 + 2 = 40 |
| Entrées de nature incertaine ou contredite | IOC-025, IOC-026, IOC-037, IOC-038 (valeur tronquée) |
| Indicateurs extraits pendant l'analyse (séparés) | 15, voir `02-Artefacts/Indicateurs-extraits.csv` |

Aucune valeur n'a été envoyée à un service tiers (les valeurs sont des plages de documentation RFC 5737 et des domaines `.test`).

## 2. Cotes Admiralty : cotes du SOC et cotes de l'équipe

Les cotes du SOC (colonne « Cote SOC ») sont reprises comme données. La cotation de l'équipe sépare **fiabilité de la source (A à F)** et **crédibilité de l'information (1 à 6)**. Ce n'est ni une probabilité ni l'équivalent d'une « confiance moyenne ».

| Source | Fiabilité | Justification |
|---|---|---|
| Dossier d'artefacts (SRC-001) | **C** (plafonnée faute de source indépendante) | Fournisseur identifié, structure cohérente ; provenance amont inconnue ; 21 incohérences internes |
| Fiches binaires (SRC-003) | **C** | Empreintes cohérentes avec le CSV, taille de BIN-002 corroborée ; échantillons absents |
| Alertes SIEM (SRC-004) | **C** | 12 sur 12 retrouvées dans le journal ; mapping ATT&CK du SIEM à corriger deux fois |
| Journal brut (SRC-006) | **C** | 12 lignes ISO concordantes ; fuseau du bruit inconnu |
| Mémo SOC (SRC-005) | **D** | Daté avant les faits qu'il décrit |
| Documentation officielle ATT&CK (SRC-009) | **A** | Source officielle |

Crédibilité de l'information : 3 (possiblement vraie) pour ce qui est observé dans un journal ; 4 (douteuse) pour ce qui est seulement déclaré ; 5 (improbable ou contredite) pour les éléments en conflit (IOC-025, 026, 038, 018) ; 6 (ne peut être jugée) pour ce qui renvoie à une source absente (IOC-028, 035). **Aucune information n'atteint 1 ou 2** : la confirmation par une source indépendante n'existe pas dans le lot (les artefacts viennent du même fournisseur).

## 3. Corrélations : nature réelle des liens

| Lien | Nature | Statut |
|---|---|---|
| Empreintes des fiches = lignes IoC 1 à 9 | égalité exacte de valeurs | CORROBORÉ (même fournisseur) |
| Taille 421376 (fiche BIN-02) = taille de la réponse Squid | égalité exacte d'une propriété | CORROBORÉ, pas un lien de hash |
| Domaine IOC-013 vu dans l'URL de la ligne 2 | égalité exacte de valeur | OBSERVÉ |
| IOC-013 vers IOC-019 (résolution), IOC-014 vers IOC-020 | relation réseau **déclarée** | DÉCLARÉ, aucun journal DNS |
| Certificat partagé par les serveurs de commande (IOC-033), « même certificat » (IOC-016) | relation de certificat **déclarée** | DÉCLARÉ, aucun artefact TLS |
| Séquence 08:30, 08:31, 08:41, 08:46, 09:15 (poste d'entrée) | lien temporel | HYPOTHÈSE de chaîne causale |
| Balayage 3 mars, RDP 4 mars, injection 4 mars | lien temporel | HYPOTHÈSE |
| LSASS 14:07, compte 14:12, archive 14:45, sortie 15:31 | lien temporel + déclaration de la fiche BIN-03 | HYPOTHÈSE forte |
| Similarité de code ou de capacité avec un outil connu | aucune mesure possible (échantillons absents) | NON TESTÉ |
| Rapprochements d'outil (MISP, OpenCTI) | MISP : 0 corrélation avec d'autres événements ; OpenCTI : 0 entité préexistante sur 37 valeurs testées | aucun lien externe constaté |

## 4. Tableau des 40 entrées

Colonnes : « Présent dans » = où la valeur apparaît dans les originaux ; « Cote équipe » = fiabilité de la source et crédibilité de l'information.

| ID | Type | Valeur (normalisée) | Présent dans | Cote SOC | Cote équipe | Statut analytique | Justification |
|---|---|---|---|---|---|---|---|
| IOC-001 | sha256 | `2d10d13c3f3a045dc12a48e0a484018c053d0e83c607…` | fiche | A1 | **C4** | DECLARE (fiche BIN-01) | fiche seule ; échantillon absent ; parent winword vs .xlsm (I-18) |
| IOC-002 | sha1 | `4911bfb2fa8f76909de149299ef05e6b1455ea24` | fiche | A1 | **C4** | DECLARE (fiche BIN-01) | fiche seule ; échantillon absent ; parent winword vs .xlsm (I-18) |
| IOC-003 | md5 | `8ba35251cca8daa4a05331bba8f95b05` | fiche | A2 | **C4** | DECLARE (fiche BIN-01) | fiche seule ; échantillon absent ; parent winword vs .xlsm (I-18) |
| IOC-004 | sha256 | `cdf03e90d85977619f7881a13f59a275812dbf0e4ae2…` | fiche | A1 | **C3** | CORROBORE en partie (taille 421376 = journal l.2) | la taille concorde mais deux artefacts du même fournisseur ne sont pas indépendants ; le hash n'est pas recalculable |
| IOC-005 | sha1 | `ca91f74f2438d710e130a5a413b2c75219c9d5a9` | fiche | A1 | **C3** | CORROBORE en partie (taille 421376 = journal l.2) | la taille concorde mais deux artefacts du même fournisseur ne sont pas indépendants ; le hash n'est pas recalculable |
| IOC-006 | md5 | `91678506a5474354f1ceb4c12c3c56dd` | fiche | A2 | **C3** | CORROBORE en partie (taille 421376 = journal l.2) | la taille concorde mais deux artefacts du même fournisseur ne sont pas indépendants ; le hash n'est pas recalculable |
| IOC-007 | sha256 | `f4109cd2860816d568c5581edf8ed5df28d35471fa8f…` | fiche | A1 | **C4** | DECLARE (fiche BIN-03) | fiche seule ; outil générique selon la fiche |
| IOC-008 | sha1 | `d1a4a3501bd1b1d9bc32ade2b4add3cb135e36b8` | fiche | A1 | **C4** | DECLARE (fiche BIN-03) | fiche seule ; outil générique selon la fiche |
| IOC-009 | md5 | `3435016f3f2aacce36b71abb636cfc64` | fiche | A2 | **C4** | DECLARE (fiche BIN-03) | fiche seule ; outil générique selon la fiche |
| IOC-010 | sha256 | `81aa487933bb715f9dabd1755eff6cfd13a9c635e1b3…` | aucun | B2 | **C4** | DECLARE (IoC dérivé, aucune capture) | empreinte d'un objet non fourni (mémoire, archive) ; IOC-011 rattaché à BIN-002 par le SOC sans lien technique |
| IOC-011 | sha256 | `8772b487de8ea8d30a7630e906afa95dcbf4a75f5915…` | aucun | B2 | **C4** | DECLARE (IoC dérivé, aucune capture) | empreinte d'un objet non fourni (mémoire, archive) ; IOC-011 rattaché à BIN-002 par le SOC sans lien technique |
| IOC-012 | sha256 | `a0e1f129a0155e96b0e04e8bc26b0d07fa8fb47c79f6…` | aucun | B2 | **C4** | DECLARE (IoC dérivé, aucune capture) | empreinte d'un objet non fourni (mémoire, archive) ; IOC-011 rattaché à BIN-002 par le SOC sans lien technique |
| IOC-013 | domain | `cdn-svc-update.test` | journal+alerte | B2 | **C3** | OBSERVE (URL dans journal l.2) | domaine vu dans la requête proxy ; « jamais vu » non vérifiable |
| IOC-014 | domain | `api-telemetry-eu.test` | alerte | B2 | **C3** | ALERTE SEULE (détail de l'alerte 4) | absent du journal brut ; l'IP vue est 198.51.100.24, le lien domaine vers IP est déclaré (IOC-020) |
| IOC-015 | domain | `mail-secure-login.test` | aucun | C2 | **C4** | DECLARE | page d'hameçonnage ; ni courriel ni journal fournis |
| IOC-016 | domain | `static-assets-cache.test` | journal+alerte | C3 | **C4** | OBSERVE (journal l.11) | requête vue le 6 mars mais « repli C2 » est une annotation ; infrastructure « vue » le 3 mars (I-11) |
| IOC-017 | domain | `helios-energy-portal.test` | aucun | B3 | **C4** | DECLARE | domaine d'usurpation ; aucun artefact |
| IOC-018 | domain | `update-win-msft.test` | aucun | C3 | **C5** | DECLARE | contexte « nom de tâche planifiée associé » incompréhensible (I-14) |
| IOC-019 | ipv4 | `198.51.100.23` | aucun | B2 | **C4** | DECLARE (résolution) | résolution déclarée, non vérifiée, aucun journal DNS |
| IOC-020 | ipv4 | `198.51.100.24` | journal | B2 | **C3** | OBSERVE (journal l.4) | connexion vue ; rôle de balise = annotation ; une seule ligne |
| IOC-021 | ipv4 | `203.0.113.14` | aucun | B2 | **C4** | DECLARE | « C2 principal » jamais vu dans un journal ; relation avec 198.51.100.24 non établie (I-12) |
| IOC-022 | ipv4 | `203.0.113.15` | aucun | C3 | **C4** | DECLARE | repli déclaré, jamais vu dans un journal |
| IOC-023 | ipv4 | `198.51.100.40` | aucun | C2 | **C4** | DECLARE | hébergement d'hameçonnage ; aucun artefact |
| IOC-024 | ipv4 | `203.0.113.28` | journal+alerte | B2 | **C3** | OBSERVE (journal l.10) | volume anormal observé ; contenu inconnu |
| IOC-025 | ipv4 | `198.51.100.55` | journal+alerte | B3 | **C5** | OBSERVE mais NATURE INCONNUE (journal l.5) | IP publique source d'un balayage interne : pseudonymisation (HYP-003), scanneur externe (HYP-004) ou erreur ; ne pas diffuser comme offensif |
| IOC-026 | ipv4 | `203.0.113.44` | aucun | C3 | **C5** | DECLARE ET CONTREDIT | alerte 7 dit source interne, l'IoC dit externe (I-04) |
| IOC-027 | ipv4 | `198.51.100.61` | aucun | C4 | **C5** | DECLARE | passive DNS partagé avec « D-04 » (référence non résolue, I-13) ; non vérifiable |
| IOC-028 | ipv4 | `203.0.113.60` | aucun | D4 | **C6** | NON VERIFIABLE | rapport public non fourni (cote D4 du SOC) ; aucune recherche externe lancée |
| IOC-029 | url | `https://cdn-svc-update.test/win/svchost_upda…` | journal | B2 | **C3** | OBSERVE (journal l.2) | GET 200 de 421376 octets ; contenu non vu |
| IOC-030 | url | `https://mail-secure-login.test/owa/auth` | aucun | C2 | **C4** | DECLARE | URL du dossier ; aucun artefact d'observation |
| IOC-031 | url | `https://api-telemetry-eu.test/v2/beacon` | aucun | B2 | **C4** | DECLARE | URL du dossier ; aucun artefact d'observation |
| IOC-032 | url | `https://helios-energy-portal.test/hr/doc` | aucun | B3 | **C4** | DECLARE | URL du dossier ; aucun artefact d'observation |
| IOC-033 | sha1-cert | `bda5d6c36e3ff362f9ce0957370a429fff58eb37` | aucun | B2 | **C4** | DECLARE | empreinte de certificat ; aucun certificat ni journal TLS fourni ; « partagé par les C2 » non étayé |
| IOC-034 | sha1-cert | `0315d14dd4b9095a10e359cbaf4129f0a6322a59` | aucun | C3 | **C4** | DECLARE | empreinte de certificat ; aucun certificat ni journal TLS fourni ; « partagé par les C2 » non étayé |
| IOC-035 | sha1-cert | `1e8bd87af841cda6441306558f11d973eb0a5601` | aucun | C4 | **C6** | NON VERIFIABLE | pivot vers une campagne de janvier 2026 non fournie (cote C4 du SOC) |
| IOC-036 | host | `MicrosoftEdgeUpdateTaskMachine` | journal+alerte+fiche | A2 | **B3** | OBSERVE (journal l.3) | création de tâche vue ; action et compte inconnus ; libellé Sysmon non standard (I-20) |
| IOC-037 | host | `svc-backup-temp` | journal+alerte | B2 | **C4** | OBSERVE ET CONTRADICTOIRE (journal l.6 et l.9) | compte utilisé 36 h avant sa création (I-03) |
| IOC-038 | host | `HKCU\...\Run\WinTelemetry` | aucun | A2 | **C5** | DECLARE (valeur tronquée) | « HKCU\...\Run\WinTelemetry » : valeur incomplète dans la source |
| IOC-039 | host | `C:\Windows\Temp\~df3a9.tmp` | aucun | B2 | **C4** | DECLARE | fichier temporaire ; aucun artefact |
| IOC-040 | host | `comptabilite-07` | journal+alerte | A1 | **B2** | OBSERVE (hôte dans les journaux) | actif victime, pas un indicateur offensif |
