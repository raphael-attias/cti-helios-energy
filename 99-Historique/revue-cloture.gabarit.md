# Revue de clôture, 2026-10-06 (seconde passe)

> **Mise à jour du 2026-10-07 : le document de référence est `Audit-final-criteres.md`** (audit complet, preuves, contrôles live `Controle-live-2026-10-07.md`). Cette revue reste l'historique de la passe du 2026-10-06 ; les corrections postérieures y sont signalées.

Cette revue vérifie ce qui a été annoncé comme produit. Elle ne crée aucun objet dans les plateformes, ne touche à aucun connecteur et ne refait aucune ingestion. Les écritures faites pendant la revue sont locales : documents, bundle STIX régénéré, PDF, matrice, scripts. **La mission n'est pas validée à 100 %.**

| Niveau | Sens |
|---|---|
| Terminé techniquement | le livrable existe et l'outil correspondant s'est exécuté sans erreur |
| **VALIDÉ** (statut de la matrice) | critères du §14 du brief : livrable existant, contenu attendu présent, preuve traçable, contrôle exécuté, limites écrites. **N'exige pas l'avis du commanditaire** |
| Relu par l'utilisateur | l'utilisateur a lu et accepté le contenu (rien n'a été relu à ce jour) |
| Validé par le commanditaire | suivi à part (`relu_par_commanditaire` = non partout) |

## 0. Ce que la seconde passe a corrigé ou établi

| Point | Résultat |
|---|---|
| Formulation du bilan | « production intacte » remplacé par : **production modifiée, sans effet de bord détecté dans le périmètre des contrôles réalisés** (liste au 1.1) |
| Insertion SQL de l'organisation MISP | motif, méthode, contrôles, limites, retour arrière : `00-Pilotage/Insertion-organisation-MISP.md` ; aucune nouvelle écriture en base |
| 35 vers 36 exigences | expliqué et listé avec origine : `00-Pilotage/Exigences-origine.md` |
| 24 exigences « à contrôler » | tous les contrôles techniques réalisables exécutés (`controles-exigences.py`, @@NCTL@@ contrôles dont @@NKO@@ KO tous sur REQ-15, `Controles-exigences.csv`) ; **23 passent à VALIDÉ** ; REQ-15 reste ouverte (définition de « objets liés ») ; relectures humaines utiles listées |
| Défauts réels trouvés pendant les contrôles | journaux J2 à J5 incomplets (sections exigées manquantes), ANSSI/CNIL/FIRST absents du registre des sources, `first_observed` de 5 `observed-data` = date d'ingestion, graphe annoncé sur la page de l'incident alors qu'il est sur le rapport, pièce jointe tactique d'OpenCTI périmée : **tous corrigés localement ou documentés** |
| STIX vs plateformes | `06-STIX-Graphe/Ecarts-bundle-plateformes.md` : 11 écarts, dont 2 défauts réels des plateformes (E3 dates MISP, E10 PDF OpenCTI) |
| ATT&CK | méthode et vérification contre les bundles officiels v18.1, v19.0, v19.2 : `04-Analyse/Version-ATTACK.md` |
| OpenCTI | graphe, onglet Indicateurs, liens, PDF diagnostiqués : `05-Plateformes/Diagnostic-OpenCTI.md` |
| Classification | `05-Plateformes/Classification-et-validite.md` (propositions P1 à P4 à approuver) |
| Restes en production | `00-Pilotage/Options-restes-production.md` (options A à D séparées) |
| Dépôt Git | `11-Validation/Depot-Git-confirmation.md` : confirmation exacte prête, essai à blanc fait ; **vous avez choisi de créer le dépôt vous-même (2026-10-07)** : commandes dans `Depot-Git-confirmation.md` §6 |

## 1. État final de l'infrastructure

### 1.1 Formulation exacte et périmètre des contrôles

**La production a été modifiée** par la mission (tableau 1.2). **Aucun effet de bord n'a été détecté dans le périmètre des contrôles réalisés** : (a) Wazuh : démons en marche, erreurs récurrentes antérieures au changement, aucune intégration ni réponse active déclenchée (niveaux 4 à 7) ; (b) MISP : tables relues en lecture seule (`CHECK TABLE` OK, aucune référence orpheline, événements 1 à 5 inchangés) ; (c) OpenCTI : aucun domaine créé, aucune trace dans les journaux Google DNS et IPinfo, aucun envoi Jira constaté, 439 détections = 435 + 4 (aucune ajoutée par le connecteur Wazuh depuis le 2026-10-03). **Non contrôlés** : effets sur des événements entrants pendant le redémarrage de 41 s de Wazuh ; effets d'une future montée de version de MISP sur l'organisation insérée en SQL ; état du cache applicatif MISP.

| Point Wazuh | Constat | Preuve |
|---|---|---|
| Santé du manager | **11 démons en marche sur 15** ; les 4 arrêtés sont ceux que la configuration d'un nœud unique désactive (cluster `disabled`, courriel `no`, agentless, csyslog). **Correction** : l'énoncé « 15 sur 15 » du 2026-10-06 était inexact | `wazuh-control status`, relu le 2026-10-07 (`Controle-live-2026-10-07.md`) |
| Fichiers ajoutés | `etc/decoders/helios_decoders.xml` (14 décodeurs, sha256 `bffcf457…6535` = `07-Detection-Tests/wazuh/helios_decoders.xml`) et `etc/rules/helios_rules.xml` (15 règles, sha256 `999190ee…2052f` = `helios_rules_prod.xml`) ; dans le volume `single-node_wazuh_etc` | sha256 recalculés dans le conteneur |
| Alertes | 27 documents `helios_challenge`, vus dans le dashboard | API et captures |

### 1.2 Journal des changements faits en production

Preuve d'autorisation : **pas d'approbation par opération dans la conversation.** Base : l'instruction générale du tour 5 (« réaliser l'ingestion et les tests sur l'infrastructure existante après résolution des risques », avec la liste des actions exigeant une autorisation spécifique : blocage CrowdSec, réponse active Wazuh, publication externe, envoi Jira ou TheHive, purge de file), plus les confirmations des outils. Aucune des actions à autorisation spécifique n'a été faite.

| # | Plateforme, objet | État initial | Opération | Date (UTC) | Impact observé | État final |
|---|---|---|---|---|---|---|
| 1 | MISP, organisation | une organisation, `stormlab` | INSERT SQL de `CHALLENGE-FICTIF` (**méthode directe en base** : voir `Insertion-organisation-MISP.md`) | ≈ 09:58 | aucun | id 2, `CHECK TABLE` OK |
| 2 | MISP, utilisateur | utilisateurs d'id 1 à 4 | `cake user create` (Publisher, org 2) et clé d'API dédiée | ≈ 09:58 | aucun | id 5 ; fichier de clé supprimé (vérifié) ; clé valide en base |
| 3 | MISP, événement 6 | aucun | création (diffusion 0, non publié, `tlp:amber`), 5 objets, 8 galaxies, 1 rapport d'événement | 10:00 à ≈ 10:04 | invisible hors org 2 et administrateurs (**vérifié avec le compte du connecteur**) ; 0 corrélation | présent, intact |
| 4 | OpenCTI, création | aucune entité de la mission | 47 objets étiquetés, 3 organisations, 6 labels, 11 références externes, 26 relations dont 6 `based-on`, 4 détections, 2 PDF joints ; heures `created_at` : 10:07:51 à 10:08:34, relations jusqu'à 10:14:22, rapport et notes 11:59:21 | voir colonne | voir 1.1 | présent |
| 5 | OpenCTI, une relation | relation de ma création vers l'entité minimale `T1070.001` | suppression de **ma** relation, création vers `T1685.005` | ≈ 10:14 | aucun sur des objets tiers | à jour |
| 6 | Wazuh, fichiers | aucun fichier `helios_*` | 2 fichiers nouveaux, `wazuh-analysisd -t`, redémarrage 41 s | 10:26:01 à 10:26:42 | analyse interrompue ≈ 41 s ; perte d'événements non mesurée | en place |
| 7 | Wazuh, rejeu | aucune alerte `helios_challenge` | `POST /events` : 3 puis 42 | 10:26:57 à 10:27:25 | 27 alertes (niveaux 4 à 7) | présentes |
| 8 | Hôtes | n/a | conteneur de test jetable, scripts dans `/tmp` | tout au long | aucun | nettoyés (vérifié sur pharos, hiboux, misp, wazuh) |

Pendant la revue : lectures seules, avec une précision : **un test de visibilité a utilisé la clé de lecture du connecteur MISP** (lue dans son conteneur, jamais affichée) ; il a mis à jour la date de « dernier accès » de ce compte.

### 1.3 Connecteur MISP vers OpenCTI

| Point | Constat |
|---|---|
| État | conteneur `misp-connector-misp-1` **en fonctionnement** (démarré le 2026-09-23 18:15), mais **aucun accès à MISP relevé depuis le 2026-09-23** avant mon test ; antérieur à la mission (je ne l'ai ni arrêté ni modifié). Les termes « pause » des documents précédents sont à lire ainsi : arrêt de fait des interrogations, pas arrêt du conteneur |
| Compte MISP utilisé | id 4, organisation 1, rôle lecture seule, pas administrateur : **ne voit pas l'événement 6** (réponse vide à une recherche sur cet identifiant) |
| Filtres | aucun ; paramètres disponibles : `import_owner_orgs_not`, `import_creator_orgs_not`, `import_distribution_levels`, `import_tags_not`, etc. |
| Décision | **non repris, non filtré** ; options dans `Options-restes-production.md` (D) |

### 1.4 Retours arrière et corrections préparés, NON EXÉCUTÉS

`Options-restes-production.md` (Wazuh, OpenCTI, MISP, filtre connecteur), `Insertion-organisation-MISP.md` (§5), `Diagnostic-OpenCTI.md` (C1 à C4), `Classification-et-validite.md` (P1 à P4), `Ecarts-bundle-plateformes.md`. Cibles exactes : `05-Plateformes/IDs-cibles-retrait.json`.

## 2. Contrôle des interfaces (2026-10-06, session Chrome déjà connectée)

| Plateforme | Contrôlé | Résultat | Réserve |
|---|---|---|---|
| MISP, événement 6 | oui (identité du serveur vérifiée : empreinte SHA-256 `29:C8:DC:CF:…:38:16` identique sur le serveur et sur le réseau ; aucune protection du navigateur désactivée) | 46 attributs dont 5 objets, 8 galaxies, diffusion 0, non publié, 1 rapport d'événement | tag `tlp:amber` (`tlp:red` n'existe pas dans MISP) ; tailles en attributs libres |
| OpenCTI rapport | oui | 28 entités en vue entités, **graphe de connaissance affiché**, onglet Données : 2 PDF | PDF tactique = ancienne version |
| OpenCTI incident | oui | 20 entités, 8 indicateurs sous « Entités liées », vue relations | pas de graphe sur la page incident (écran inexistant dans la version) ; onglet Indicateurs vide (`related-to`) |
| OpenCTI listes filtrées | oui | données observées 4, détections 4, observables 27, indicateurs 8 | libellés de plateforme « VRAI POSITIF », « 5 - Improbable » |
| PDF joints | oui | stratégique : s'ouvre, 2 pages, lisible ; tactique : s'ouvre, 10 pages | version périmée (C3) |
| Wazuh Discover | oui | 27 hits, `rule.id` sur 27/27 | heure de traitement, pas heure d'origine |

Douze captures dans `11-Validation/preuves-consultation/`. Aucune donnée n'a été modifiée par l'interface.

## 3. Réconciliation des tests

`07-Detection-Tests/Reconciliation-tests.md` (unité, jeu, outil, environnement, commande, preuve, résultat, limites) : 162 couples règle × événement (Sigma, SQLite) ; 410 événements ; 45 cas Wazuh × 4 niveaux = 180 lignes (non indépendantes) ; 27 positifs et 18 négatifs ; 27 alertes indexées, vues dans le dashboard. Aucun taux de faux positifs de production n'est mesuré.

## 4. Revue STIX

`06-STIX-Graphe/Rapport-validation-STIX.md` et `Ecarts-bundle-plateformes.md`. Corrections locales : T8 (ids SCO UUIDv5), T9 (relation `downloaded-from`), T10 (`valid_from` par indicateur), T11 (`based-on` vers `observed-data`), **T12 (5 `observed-data` datés de l'ingestion : défaut trouvé pendant la seconde passe)**. Résultat : valide, 0 erreur, **82 avertissements classés** (63 identifiants déterministes assumés, 8 `src_port` absents, 8 références MITRE sans hash, 3 `based-on`). Le validateur refuse désormais un `observed-data` ou un `valid_from` hors mars 2026 (l'ancien bundle serait rejeté). Graphe, validation et inventaire sont régénérés depuis le bundle corrigé ; `Derives-du-bundle.txt` note le hash du bundle dont ils dérivent et `verifier-manifest.py` le contrôle.

**Les corrections du bundle ne sont pas dans MISP ni OpenCTI** : voir les 11 écarts. Aucun n'est appliqué.

## 5. Exigences

Origine et réconciliation : `00-Pilotage/Exigences-origine.md`. Contrôles : `11-Validation/Controles-exigences.csv`. Le tableau suivant est généré depuis la matrice.

@@REQ_TABLE@@

Sur les 36 exigences officielles : **@@NV@@ VALIDÉES (critères du §14)**, REQ-15 À CONTRÔLER (arbitrage de définition, Q14), REQ-36 @@S36@@, REQ-04 BLOQUÉE (échantillons non fournis, imputable au dossier). **Aucune n'est relue par le commanditaire.** Compétences : les 8 lignes de `Couverture-competences.md` sont complètes (REQ-32), sans validation de formateur.

## 6. ATT&CK

Méthode retenue : **cartographie selon la version actuelle (v19.2), avec correspondance v18.1** (justification dans `04-Analyse/Version-ATTACK.md`). Vérification faite par script contre les trois bundles officiels : les 8 techniques OBSERVÉES existent, sont actives et portent le même nom ; **seule T1070.001 (v18.1) devient T1685.005 (v19)** ; les tactiques « Defense Evasion » deviennent `stealth` et `defense-impairment` en v19. Les 10 autres techniques de la matrice sont aussi actives dans les deux versions. Ce que cela n'établit pas : que chaque technique est démontrée par les artefacts, ni que les descriptions n'ont pas changé.

## 7. Sources réglementaires

CNIL, ANSSI et **Légifrance (article L1332-6-2, en vigueur depuis le 2013-12-20)** lus le 2026-10-06 ; NIS 2 : sources secondaires seulement (promulgation en attente), état à revérifier sur une source officielle avant tout usage.

## 8. Dépôt Git

Non créé : **le chemin `/Users/rapatt/Projet/cti-helios-energy` n'existe pas (vérifié le 2026-10-07)**. Le dépôt est obligatoire depuis le sujet initial. Création locale **non approuvée** le 2026-10-07 (voir `Audit-final-criteres.md`). Confirmation exacte, manifeste d'inclusion, essai à blanc, étapes séparées et commandes à lancer : `Depot-Git-confirmation.md`. REQ-36 passe à VALIDÉ après la vérification réelle du dépôt créé (`verify` lancé sur le dépôt ; je peux le relancer sur demande).

## 9. Bilan final

**Exigences contrôlées et satisfaites** : @@NV@@ sur 36 officielles (voir 5), plus SUP-01 (avec réserves) et OPT-03.

**Limites imputables au dossier fourni** : aucun échantillon binaire (REQ-04), une seule ligne de balise, journal Security effacé, aucune source indépendante pour l'attribution, SIIV, secteur, équipe et temps non fournis (le statut OIV est fourni par l'énoncé), glossaire TLP du sujet absent, sujet officiel absent.

**Autres limites** : aucun taux de faux positifs de production ; jeux de test écrits par l'équipe ; aucune relecture par un tiers.

**Opérations attendant votre approbation** : (1) **dépôt Git** : création locale (copie, vérification, init, commit, sans remote) ; (1 bis) investigation et 5 RFI OpenCTI : **créées le 2026-10-07 après approbation** (`Suivi-RFI.md`) ; (2) retrait des règles Wazuh (B) ; (3) retrait OpenCTI (C1) et MISP (C2) ; (4) filtrage puis reprise du connecteur (D) ; (5) corrections plateformes facultatives : C1 `indicates`, C3 PDF tactique, P1 marquage des organisations, P2 `tlp:red`, P3 `valid_from`, E3 `first_seen` MISP.

**Contrôles nécessitant votre session graphique** : aucun contrôle bloqué ; la création d'un tag `tlp:red` dans MISP (P2) et l'ajout de `first_seen` aux attributs d'objets demandent un compte administrateur de MISP.

**Arbitrages du commanditaire** : définition des « objets liés » (Q14, RFI-05 : 20, 24, 34 ou 99 selon la définition) ; niveau TLP commun (Q29) ; liste officielle des exigences (Q15) ; maintien ou retrait du fictif (Q26) ; reprise du connecteur (Q28).
