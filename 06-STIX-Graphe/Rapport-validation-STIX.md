# Rapport de validation STIX 2.1

Date : 2026-10-06, mis à jour le 2026-10-10 (transformation T14). Fichiers : `Bundle-STIX.json` (final), `Export-MISP-brut.json` (export MISP réel, intact), `Rapport-validation-sortie.txt` (sortie réelle des validateurs), `Inventaire-objets-STIX.csv`, `Inventaire-liaison-STIX.csv` et `Justification-25-objets-lies.md` (comptage des objets liés), scripts `generer-bundle.py`, `valider-bundle.py`, `generer-graphe.py`.

## 1. Origine du bundle et transformations

Le bundle part de l'**export STIX 2.1 réel de MISP** (événement 6, produit par le convertisseur MISP, API `restSearch` avec `returnFormat=stix2`). Ce n'est pas un bundle construit de toutes pièces ; **mais l'export brut ne suffit pas** : il ne contient ni indicateurs (tous les attributs sont `to_ids=false`), ni techniques ATT&CK, ni cluster. Le bundle final est donc l'export, transformé comme suit :

| # | Transformation | Raison |
|---|---|---|
| T1 | Export brut conservé tel quel dans `Export-MISP-brut.json` | traçabilité |
| T2 | `observed-data` : `last_observed` ramené à `first_observed`, `number_observed` = 1 (28 objets) | MISP met la date de création de l'export quand l'attribut n'a pas de `last_seen` : sans correction, l'observation s'étendrait faussement jusqu'au 2026-10-06 |
| T3 | Ajout d'objets analytiques : 8 `attack-pattern` (techniques OBSERVÉES), 8 `indicator`, 3 `malware` (DÉCLARÉS par les fiches), 1 `campaign` (**cluster non attribué**), 5 identités (équipe, victime, 3 systèmes), 4 notes, 1 `report` | absents de l'export |
| T4 | Ajout de 31 relations avec statut (`labels` : observe 12, hypothese 13, declare 6) et `confidence` ; **T13 en ajoute 12** (voir plus bas) : 43 relations ajoutées en tout (observe 21, hypothese 15, declare 7) | sémantique justifiée par les artefacts |
| T5 | Aucune relation vers un acteur, un groupe ou une famille nommée | attribution non établie |
| T6 | Retrait des 7 objets `x-misp-attribute` (types personnalisés non validables) ; conversion : `size-in-bytes` vers `size` des `file` des fiches, compte vers `user-account`, nom de tâche, valeur de registre tronquée et hôte vers une note | conformité STIX |
| T7 | Export réalisé avec `excludeGalaxy` : l'export avec galaxies échoue (erreur PyMISP « le champ distribution ne peut pas être défini sur un cluster de galaxie par défaut », MISP 2.5.46) | limite de l'outil ; les 8 galaxies restent attachées dans MISP et apparaissent comme étiquettes `labels` du `grouping` |
| T8 | **Révision de clôture** : identifiants des 39 observables (SCO) recalculés de façon déterministe (UUIDv5, espace de noms STIX, propriétés contributrices, bibliothèque `stix2`) ; 466 références réécrites et revérifiées | l'export MISP donnait des UUID aléatoires, la spécification demande des UUIDv5 pour les SCO (38 avertissements) |
| T9 | Révision de clôture : la relation `downloaded-from` entre deux `observed-data` (export MISP) devient `related-to` entre les SCO sous-jacents (fichier vers URL) | le type exporté n'a pas de sens pour des `observed-data` ; **l'écart avec l'export est assumé et tracé** |
| T10 | Révision de clôture : `valid_from` de chaque indicateur = horodatage de la première alerte qui le porte (2026-03-02T08:31Z à 2026-03-06T03:10Z) | l'ancienne date uniforme (08:30Z) ne correspondait à aucun fait |
| T11 | Révision de clôture : `indicator based-on` pointe vers l'`observed-data` (cible suggérée) quand il en existe un pour l'observable | 5 avertissements de bonnes pratiques en moins |
| T12 | Révision de clôture : 5 `observed-data` issus d'**objets** MISP (3 `file`, 2 `domain-ip`) avaient `first_observed` = date d'ingestion (2026-10-06 10:00) : MISP n'a pas de `first_seen` sur les attributs d'objets et exporte la date de création. Remplacée par la plus ancienne « première vue » des IoC de l'objet (2026-03-02 08:30 à 2026-03-05 14:05) ; le validateur refuse désormais tout `observed-data` ou `valid_from` hors mars 2026 | **défaut découvert pendant la revue** ; la correction n'existe que dans le bundle local ; un nouvel export MISP le reproduirait |
| T13 | **2026-10-07** : ajout de 3 `tool` (`powershell.exe` et `wevtutil.exe` observés dans le journal brut, `schtasks.exe` déclaré par le détail de l'alerte 3 seulement) et de 4 `infrastructure` (hébergement du téléchargement, destination de la balise, destination de la sortie : observées ; repli : **hypothèse**, contredite par I-11), reliés à la campagne par `uses` et aux observables existants par `consists-of` (12 relations) | éléments prouvés par les artefacts et omis : voir `Justification-25-objets-lies.md` (preuve de chaque ajout) ; aucun malware, acteur ni échantillon ajouté |
| T14 | **2026-10-10** : chaque objet porte sa source et sa date de collecte. Les 39 observables (SCO) reçoivent `x_helios_source` (fichier, IoC et ligne du dossier), `x_helios_collected_at` (date d'acquisition de l'inventaire, 2026-10-06T09:05:00Z) et `x_helios_admiralty` (cote de l'équipe, `02-Artefacts/Cotes-Admiralty-IoC.csv`) ; la relation `related-to` exportée par MISP sans auteur reçoit `created_by_ref`, `confidence` 15 et le statut `declare` ; les 2 identités sans référence reçoivent une `external_references`. Aucun objet ajouté, comptages inchangés (152). |

**Ce bundle n'est pas un export MISP « pur »** : il en dérive avec les transformations ci-dessus. L'exigence « bundle depuis le renseignement structuré dans MISP » est satisfaite pour sa base et ses SCO, **pas** pour les objets ajoutés (T3, T4).

## 2. Méthode de provenance par type d'objet

| Type | Provenance portée par | Remarque |
|---|---|---|
| identity, grouping, observed-data, note (MISP) | `created_by_ref` = organisation MISP CHALLENGE-FICTIF | export |
| attack-pattern, indicator, malware, campaign, identités, notes, report, relations (ajouts) | `created_by_ref` = identité « Équipe CTI » + `external_references` (source « Dossier Helios », identifiant ART, ALERT ou IOC, ligne de journal) | conforme : `external_references` est une propriété autorisée de ces types |
| Observables (file, domain-name, ipv4-addr, url, x509-certificate, network-traffic, user-account) | **ni `created_by_ref` ni `external_references` (propriétés absentes du schéma des SCO)** ; provenance portée par l'`observed-data` qui les référence, par le `report` et par `Export-MISP-brut.json` | aucun champ non conforme n'a été ajouté |
| Date de collecte | `created` / `modified` des SDO ; `first_observed` pour l'observation ; dates d'acquisition dans `02-Artefacts/Inventaire-IoC.csv` | les dates de première vue des IoC sont des dates de découverte |

Marquage : `TLP:AMBER` (définition de l'export MISP) sur les objets ajoutés ; cohérent avec MISP (`tlp:amber`) mais **différent d'OpenCTI (TLP:RED)** : voir section 5.

## 3. Sorties réelles des validateurs

| Outil | Version | Résultat |
|---|---|---|
| `stix2-validator` (schémas OASIS, dépôt cti-stix2-json-schemas, commit 9af1db41 du 2026-01-19, liés dans le venv car absents du paquet pip) | 3.3.1 | **valide : oui, 0 erreur, 218 avertissements** |
| `stix2.parse` (strict, `allow_custom=True`) | 3.0.2 | 152 objets analysés |
| `stix2-patterns` (8 patterns) | 2.1.2 | 8 valides, 0 erreur |
| Cohérence métier (script) | | références : 548 vérifiées, 0 non résolue ; relations prévues uniquement ; dates cohérentes ; aucun acteur nommé |

Premier essai sans les schémas : le validateur rejetait **tous** les objets avec « Cannot locate a schema » : c'était un défaut d'installation (schémas absents), pas du bundle ; corrigé en liant le dépôt de schémas.

**Résultat après T14 : valide, 0 erreur, 218 avertissements** (101 après T13 ; 82 avant T13 ; 126 avant T8 à T11). Les 19 avertissements ajoutés par T13 sont tous de type {103} : identifiants UUIDv5 des 7 nouveaux objets et des 12 nouvelles relations. Les 117 ajoutés par T14 (2026-10-10) sont tous de type {401} : 39 observables × 3 propriétés de provenance personnalisées. Le validateur ne signale **aucune erreur**, mais cela ne prouve pas la qualité analytique : la revue ci-dessous porte sur le fond.

| Type d'avertissement | Nombre | Classement | Raison / décision |
|---|---|---|---|
| {401} propriété personnalisée sans extension | 117 | **Acceptable, choix documenté (T14)** | les SCO STIX 2.1 n'ont ni `created` ni `created_by_ref` : leur source et leur date de collecte sont portées par `x_helios_source`, `x_helios_collected_at` et `x_helios_admiralty` (39 observables × 3). Le validateur préfère une `extension-definition`, qui ajouterait un objet au bundle et déplacerait tous les comptages ; la propriété préfixée `x_` est autorisée par la spécification. Chaque objet du bundle porte ainsi une source et une date (contrôlé par script : 0 objet sans). |
| {103} identifiant SDO/SRO/bundle non UUIDv4 | 82 | **Acceptable, choix documenté** | 81 identifiants sont des UUIDv5 déterministes générés par le script (régénération stable, pas de doublon à la réimportation) ; 1 est l'UUIDv1 de l'organisation MISP exportée (identité reprise telle quelle). La spécification recommande l'UUIDv4 ; aucun consommateur testé ne l'exige. Non corrigé. |
| {301} `network-traffic` sans `src_port` | 8 | **Acceptable** | le port source n'existe dans aucun journal ; l'inventer serait fabriquer une donnée |
| {302} référence `mitre-attack` avec URL sans hash | 8 | **Acceptable** | le hash est facultatif ; la page ATT&CK est évolutive (cf. `04-Analyse/Version-ATTACK.md`) |
| {202} relation permise mais non suggérée (`indicator based-on` vers SCO) | 3 | **Acceptable** | l'`observed-data` n'existe pas pour ces 3 observables (ils sont dans des objets MISP `domain-ip`) |
| {103} SCO non UUIDv5 | 38 → 0 | **Corrigé (T8)** | |
| {202} `downloaded-from` entre `observed-data`, `based-on` vers SCO | 6 → 0 | **Corrigé (T9, T11)** | |

## 4. Comptages séparés (152 objets)

Les catégories ne sont jamais mélangées : un conteneur n'est pas un objet analytique, une relation n'est pas une entité (la version précédente de ce tableau comptait à tort rapport, regroupement et notes parmi les « analytiques » : corrigé).

| Catégorie | Nombre | Détail |
|---|---|---|
| **Objets de renseignement** | **27** | 1 campaign, 3 malware, 3 tool, 4 infrastructure, 8 attack-pattern, 8 indicator |
| Actifs victimes (identités) | 4 | organisation victime et 3 systèmes |
| Observables (SCO) | 39 | 7 file, 6 domain-name, 10 ipv4-addr, 4 url, 3 x509-certificate, 8 network-traffic, 1 user-account |
| Données observées (conteneurs d'observation) | 28 | observed-data |
| Relations | 44 | 1 de l'export MISP (modifiée par T9) + 43 ajoutées |
| Conteneurs | 7 | 1 report, 1 grouping, 5 notes |
| Identités d'auteur, marquage | 3 | organisation MISP, équipe, TLP:AMBER |

**Objets liés** : la méthode, les définitions (20, 24, 34 et 99 avant T13 ; **27 objets de renseignement liés dans une même composante après T13**) et les preuves de chaque objet sont dans `Justification-25-objets-lies.md`, avec l'inventaire ligne à ligne `Inventaire-liaison-STIX.csv`. Le seuil de 25 est démontré sous la méthode principale (choix de vérification de l'équipe, non confirmé par le commanditaire) ; en retirant les 2 ajouts dont la seule base est le texte d'une alerte, il reste 25. Le chiffre « 130 sur 133 » des versions précédentes comptait aussi les 32 relations.

## 5. Cohérence analytique (revue de clôture)

| Point examiné | Constat | Verdict |
|---|---|---|
| Provenance | analytiques et identités : `created_by_ref` = équipe CTI ou organisation MISP + `external_references` (ALERT, IOC, ligne de journal) ; SCO : par `observed-data`, `report` et export brut | cohérent |
| Collection | 149 objets sur 152 sont reliés (relation ou conteneur) ; les 3 non reliés sont l'organisation MISP, le marquage TLP et le `report` lui-même ; le `report` ne référence pas non plus le `user-account` (cité seulement par une note) | cohérent |
| Relations | 44 : 21 `observe`, 15 `hypothese`, 7 `declare` + 1 de l'export ; aucune relation vers un acteur nommé ; les 8 `indicates` vers le cluster sont des **hypothèses** de confiance 15 | cohérent ; le lien indicateur-cluster reste une hypothèse |
| Patterns | 8 patterns valides ; chacun reprend exactement la valeur du SCO ciblé (contrôlé par `controle-coherence.py`) | cohérent |
| Dates des `observed-data` | `first_observed` = **date de découverte de l'IoC par le SOC** (colonne « première vue » du CSV), **pas l'heure de l'événement** ; l'observation est donc « vue par le SOC à cette date » ; **5 objets exportaient la date d'ingestion : corrigé (T12)** | **limite assumée** pour la sémantique ; **corrigé** pour les 5 dates fausses |
| `valid_from` des indicateurs | corrigé (T10) : première alerte portant l'indicateur ; `valid_until` = 2026-04-02 (choix, indicateurs historiques) | corrigé |
| Marquage | les objets ajoutés et le `grouping` portent **TLP:AMBER** (étiquette `tlp:amber` de l'événement MISP) ; **les objets OpenCTI de la mission sont TLP:RED** (choix plus strict pris à l'ingestion) ; 71 objets n'ont aucun marquage (28 `observed-data`, 39 SCO, 2 identités, 1 note, 1 relation de l'export) | **écart réel à arbitrer** : aligner MISP sur RED (balise `tlp:red`, droits d'éditeur) ou OpenCTI sur AMBER ; décision du commanditaire (Q29, arbitrage non obtenu) |
| Confiances | 32 objets à 15, 31 à 50 ; ce sont des **confiances d'analyste**, distinctes de l'Admiralty (non cotée par l'équipe) | cohérent |
| Hypothèse de cluster | la `campaign` est « non attribuée » ; aucun `intrusion-set`, `threat-actor`, famille nommée | cohérent |
| Collision d'identifiants | 152 identifiants distincts, aucune collision après T8 (vérifié par le script) | cohérent |

Conclusion : **la validité syntaxique est établie ; la qualité analytique est cohérente pour ce qui est vérifiable par script, mais elle n'est pas « validée »** (pas de relecture par un pair ni par le commanditaire ; hypothèses de rattachement non démontrées).

## 6. Régénération

`/Users/rapatt/Projet/cti-helios-env/.venv/bin/python 06-STIX-Graphe/generer-bundle.py`, puis `valider-bundle.py`, puis `generer-graphe.py`. Le graphe est généré **depuis `Bundle-STIX.json`** ; filtre documenté dans le script et dans l'image.
