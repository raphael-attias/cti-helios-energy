# Plan de modélisation OpenCTI (PROPOSITION : aucune écriture)

Date : 2026-10-06. Statut : **EXÉCUTÉ le 2026-10-06 sur l'instance existante (option B avec garde-fous levés ciblés), avec écarts de comptage : domaines non créés comme observables, 27 observables (et non 32), 35 objets en Observations (et non 40), 15 références documentaires. Voir `Verification-OpenCTI.md` section 9.** Le texte ci-dessous est le plan d'origine (comptages d'origine). Il complète `Plan-ingestion.md` (MISP) et n'autorise aucune écriture en production. Détail machine et comptages recoupés par script : `Manifeste-OpenCTI.json` (régénérable par `generer-manifeste-opencti.py`). Constats de plateforme : `Verification-OpenCTI.md`.

Objectif : que la mission se consulte dans **trois rubriques** : Analyses, Événements, Observations. Un rapport isolé ou un graphe seul ne suffit pas.

## 0. Décision préalable : où écrire ?

| Option | Isolation | Coût | Remarques |
|---|---|---|---|
| **A. Instance OpenCTI locale jetable (Docker sur le Mac), version 6.9.21 épinglée** : **recommandée** | **Technique et réelle** : aucun connecteur de production, aucun flux, aucun enrichissement externe | Docker 29.8.1 est installé, 64 Go de RAM, 1,2 To libres ; **état du démon non vérifié** ; téléchargement d'images (taille à confirmer avant accord) | Permet aussi de **contrôler l'interface réellement** ; destruction du jeu de test en fin de mission (volet écoresponsable) ; production non touchée |
| B. Production (172.16.0.4:8180) avec garde-fous | **Aucune isolation technique** : libellés, marquages et auteurs ne sont que de la traçabilité | Nul en infrastructure | Voir risques section 5 ; exige des préalables (neutraliser l'enrichissement automatique, lire les filtres du flux Jira) |
| C. Brouillon (« Draft ») de la production | Non prouvée : fonction non vérifiée sous licence Communauté | Faible | À examiner seulement si B est retenue |

Un label, un marquage TLP ou un auteur dédié **ne constituent pas une isolation technique** : ils servent à retrouver, filtrer et nettoyer.

## 1. Rubrique ANALYSES

| Objet | Nombre | Détail |
|---|---|---|
| **Report** « [CHALLENGE FICTIF] Helios Energy — Investigation CTI » | 1 | Type proposé `internal-report` ; date de publication = date de rédaction (2026-10-06), pas une date d'incident. Contenu : contexte et périmètre ; observations et conclusions documentées ; sources ; limites et incohérences ; attribution hypothétique (identifiée comme telle) ; références aux entités et relations. Conteneur de tous les objets de la mission. |
| **Notes** rattachées au rapport et à l'incident | 3 | **N-ALERTES** : registre des 12 alertes (identifiants ALERT-001 à 012, fichier:ligne, ligne de journal, traitement retenu) ; **N-LIMITES** : incohérences I-01 à I-21 et blocages ; **N-ATTRIB** : attribution hypothétique, niveau INCONNU à ce jour, indication pédagogique distinguée |
| **External-References** | 7 | Les 7 fichiers du dossier (ART-001 à ART-007), nom et sha256 en description, **sans URL ni contenu**, rattachées au rapport |
| Grouping | 0 | Exclu : n'ajoute rien au modèle choisi |
| Rapports stratégique et tactique | 0 aujourd'hui | À joindre **seulement** quand ils auront été produits et contrôlés (PDF vérifiés) ; aucun fichier n'existe à ce jour |

Sous-total Analyses : **11 objets**.

## 2. Rubrique ÉVÉNEMENTS

### 2.1 Incident (1)

« [CHALLENGE FICTIF] Helios Energy — Intrusion ». Renseigné **uniquement** avec :
- `first_seen` 2026-03-02T08:31:00Z : première **observation** du dossier (ALERT-001), pas le début de l'intrusion ; `last_seen` 2026-03-07T09:02:00Z : dernière observation (ALERT-012), pas la fin. La description le dit expressément. Alternative : laisser les deux champs vides (question Q23).
- Impacts soutenus : commande PowerShell encodée et masquée sur comptabilite-07 ; accès mémoire à lsass.exe sur dc-01 ; création puis suppression d'un compte sur dc-01 ; 2 469 135 790 octets sortis vers 203.0.113.28:8080 ; effacement du journal Security de comptabilite-07.
- **Non renseignés** : gravité, type d'incident, début et fin réels, date de détection (le mémo est daté avant les faits, I-02). Non démontrés, donc écrits comme tels : contenu et étendue de l'exfiltration, vol effectif d'identifiants, présence continue de l'attaquant.

### 2.2 Les 12 alertes : représentation

Pas 12 incidents, pas 12 sightings. Chaque alerte garde son identifiant et ses preuves dans la note **N-ALERTES** ; certaines ont en plus des objets structurés quand le modèle s'y prête :

| Alerte | Observed Data | Sighting | Autre représentation |
|---|---|---|---|
| ALERT-001 | Non (commande tronquée « ... » : observable Process faux) | Non | N-ALERTES ; Incident → uses → T1059.001, T1564.003 |
| ALERT-002 | **OD-02** (URL + domaine) | **SIG-01** | + Incident → uses → T1105 |
| ALERT-003 | Non (aucun observable adapté) | Non | N-ALERTES ; Incident → uses → T1053.005 |
| ALERT-004 | **OD-04** (IPv4) | **SIG-02** | |
| ALERT-005 | Non | Non | N-ALERTES ; T1003.001 non liée (extraction non démontrée) |
| ALERT-006 | Non (nature de 198.51.100.55 inconnue) | Non | N-ALERTES ; Incident → uses → T1046 |
| ALERT-007 | Non (chronologie contradictoire I-03) | Non | N-ALERTES ; Incident → uses → T1021.001 |
| ALERT-008 | Non | Non | N-ALERTES ; Incident → uses → T1055 (parent) ; T1055.012 non utilisée |
| ALERT-009 | Non (I-03) | Non | N-ALERTES ; aucune technique liée |
| ALERT-010 | **OD-10** (IPv4) | **SIG-03** | |
| ALERT-011 | **OD-11** (domaine) | **SIG-04** | |
| ALERT-012 | Non | Non | N-ALERTES ; T1070.001 liée seulement après vérification officielle |

- **Observed Data : 4** (OD-02, OD-04, OD-10, OD-11). Chacun : `first_observed` = `last_observed` = horodatage du journal (UTC), `number_observed` 1, références vers les observables, ligne brute en description, hôte indiqué en description (le modèle n'a pas de champ hôte).
- **Sightings : 4**, **conditionnés** à l'approbation des indicateurs correspondants : indicateur vu dans un System, fenêtre `first_seen` = `last_seen`, 1 occurrence, référence externe vers l'alerte et la ligne de journal, confiance de l'analyste.
- Aucun sighting n'est créé pour une alerte dont l'observable est incertain (006, 007, 009) ni pour une action sans indicateur (001, 003, 005, 008, 012).

### 2.3 Séparation entre dossier pédagogique et rejeu Wazuh

- **Auteurs distincts** (Organizations fictives) : « [CHALLENGE FICTIF] Dossier pédagogique (SOC Helios) » pour les observations du dossier ; « [CHALLENGE FICTIF] Équipe CTI » pour l'analyse ; « [CHALLENGE FICTIF] Rejeu Wazuh (laboratoire) » **créé seulement lors d'un rejeu approuvé**.
- **Labels** : `challenge:source=dossier-pedagogique` vs `challenge:source=rejeu-wazuh`, plus `challenge:helios-fictif` sur tout.
- Les résultats de rejeu ne réutiliseront **jamais** l'identité de production « Wazuh », et le connecteur de production `Wazuh Sightings` ne doit jamais lire un indexeur alimenté par le rejeu.
- Rappel : labels et auteurs ne sont **pas** une isolation.

Sous-total Événements : **9 objets** (1 incident, 4 données observées, 4 sightings).

## 3. Rubrique OBSERVATIONS

### 3.1 Observables : 32 objets issus des 40 entrées du dossier

| Type OpenCTI | Nombre | Origine |
|---|---|---|
| Fichier | 7 | BIN-001, BIN-002, BIN-003 (empreintes MD5, SHA-1, SHA-256 fusionnées par fiche : **9 entrées → 3 objets**) ; 3 fichiers sha256 seul (IOC-010, 011, 012) ; ~df3a9.tmp (IOC-039, nom seul) |
| Dossier | 1 | C:\Windows\Temp (IOC-039) |
| IPv4 | 10 | IOC-019 à 028 |
| Nom de domaine | 6 | IOC-013 à 018 |
| URL | 4 | IOC-029 à 032 |
| Certificat X509 | 3 | IOC-033 à 035 (empreinte SHA-1 seule, aucun certificat fourni) |
| Compte utilisateur | 1 | IOC-037 (compte du SI victime) |

**Exclus** : IOC-036 (nom de tâche : aucun type adapté), IOC-038 (valeur de clé de registre tronquée dans la source : un observable serait inventé), IOC-040 (actif victime : System, pas observable). Total 40 entrées toutes affectées (contrôle par script).

**Artefacts : 0.** Les trois fiches ne sont **pas** trois échantillons : aucun Artifact, aucun contenu binaire n'est créé ni importé. Les observables Fichier ne portent que des métadonnées déclarées (nom, taille, empreintes).

Les observables ne signifient pas « malveillant » : ils conservent leur statut analytique (déclaré, non vérifié) via labels `analytic:*` et description.

### 3.2 Indicateurs : 8 sur 40, pas 40

| ID | Pattern | Contexte de menace | Sources | Confiance de l'analyste | Limites |
|---|---|---|---|---|---|
| IND-01 | `[file:hashes.'SHA-256' = '2d10d13c…66e5']` | BIN-001, dropper (fiche) | ART-002, IOC-001 | faible (15) | échantillon absent, hash non recalculable |
| IND-02 | `[file:hashes.'SHA-256' = 'cdf03e90…8ebc9']` | BIN-002, balise (fiche) | ART-002, IOC-004, journal l.2 | faible (15) | taille corroborée, pas le hash |
| IND-03 | `[file:hashes.'SHA-256' = 'f4109cd2…135f0']` | BIN-003, extraction d'identifiants (fiche) | ART-002, IOC-007 | faible (15) | outil générique « très largement partagé » |
| IND-04 | `[domain-name:value = 'cdn-svc-update.test']` | téléchargement de BIN-002 | IOC-013, ALERT-002, journal l.2 | moyenne (50) | « jamais vu » non vérifiable |
| IND-05 | `[url:value = 'https://cdn-svc-update.test/win/svchost_update.exe']` | seconde charge | IOC-029, ALERT-002 | moyenne (50) | exécution non démontrée |
| IND-06 | `[ipv4-addr:value = '198.51.100.24']` | connexion de balise | IOC-020, ALERT-004 | faible (15) | une connexion ; rôle de C2 non démontré |
| IND-07 | `[ipv4-addr:value = '203.0.113.28']` | sortie de 2 469 135 790 octets | IOC-024, ALERT-010 | moyenne (50) | contenu inconnu |
| IND-08 | `[domain-name:value = 'static-assets-cache.test']` | « repli C2 » | IOC-016, ALERT-011 | faible (15) | annotation seule |

La confiance est celle de l'analyste dans l'échelle de la plateforme (faible 15, moyenne 50) ; **ce n'est ni une cote Admiralty ni une probabilité**. Les cotes Admiralty du SOC sont reprises en labels, marquées « non évaluées par l'équipe ». Score de la plateforme proposé bas (20) et indicateurs non marqués « détection » pour ne pas déclencher d'usage opérationnel ; `valid_until` à fixer en connaissance des règles de déclin (non lues).

Les 32 autres observables (IPv4 d'infrastructure déclarée, hameçonnage, usurpation, certificats, fichiers dérivés) **restent de simples observables**.

Sous-total Observations : **40 objets** (32 observables, 8 indicateurs, 0 artefact).

## 4. Relations et navigation

| Relation | Nombre | Fondement | Statut |
|---|---|---|---|
| Indicator → based-on → Observable | 8 | pattern et valeur identiques | certaine |
| Indicator → related-to → Incident | 8 | indicateur issu d'une observation de l'incident | faible sémantiquement, **paire à vérifier au schéma** |
| Incident → targets → Organization victime | 1 | victime du dossier | |
| Incident → targets → System | 3 | événements observés sur chaque hôte | |
| Incident → uses → Attack-Pattern **existant** | 8 | techniques **observées** seulement (T1059.001, T1564.003, T1105, T1053.005, T1046, T1021.001, T1055, T1070.001 après vérification officielle) | paire à vérifier ; les Attack-Patterns existent déjà (réutilisation, pas de doublon) |
| Domain → resolves-to → IPv4 | 2 | résolution **déclarée** (IOC-013 → 019, IOC-014 → 020), confiance faible, étiquetée « déclaré non vérifié » | |
| Indicator → sighting → System | 4 | alertes 002, 004, 010, 011 | conditionnel |
| Rapport → contient (object_refs) | tout | conteneur | |
| **Total** | **30 relations + 4 sightings** | | |

**Non créées** : toute relation vers FIN7, Carbanak ou un acteur de production (l'attribution reste une hypothèse écrite dans N-ATTRIB, jamais un lien) ; T1003.001, T1071.001, T1008, T1048.003, T1136.002, T1078 (techniques seulement probables : dans la note, pas dans le graphe) ; T1055.012 (contestée) ; T1543.003 (écartée). Aucune relation pour « remplir le graphe ».

Entités de support (hors des trois rubriques) : 3 Organizations (victime fictive, auteur dossier, auteur analyse), 3 Systems (comptabilite-07, srv-fichiers-02, dc-01), 6 labels.

## 5. Risques de fusion avec la production (option B)

| Risque | Constat | Parade |
|---|---|---|
| **Déduplication des observables** : un observable est unique par sa valeur ; une valeur déjà présente est fusionnée avec l'existant | Recherche en masse : 0 des 37 valeurs testées n'existe ; reste à tester IOC-035, 038, 039 | Rejouer la recherche juste avant écriture |
| **Enrichissement automatique tiers** : Google DNS et IPinfo sont automatiques ; ils pourraient interroger un service externe sur chaque domaine ou IPv4 créé | Non lu : portée et TLP maximal | **Préalable bloquant** : désactiver temporairement ces connecteurs (modification de production, accord requis) ou choisir l'option A |
| **Flux Jira public** | Flux `jira` public avec un consommateur ; filtres non lus | Lire les filtres ; sinon option A |
| **Wazuh Sightings** crée des sightings de production | Actif | Aucun rejeu vers l'indexeur de production |
| **Déclin et rétention automatiques** | Gestionnaires actifs, règles non lues | Lire les règles ; fixer `valid_until` en conséquence |
| **Moteur de règles** | Actif mais toutes règles désactivées, 0 inférence | Ne pas les activer |
| **Réutilisation de Attack-Patterns de production** | Les relations ajoutent des liens vers des entités partagées | Acceptable (les entités ne sont pas modifiées) ; consigné |
| **Compte administrateur principal** | Écriture avec tous les droits | Compte dédié aux droits limités |
| **Pollution des listes et recherches** | 435 sightings, 352 K observables : mélange visuel | Filtre `challenge:helios-fictif` |
| **File MISP saturée** (227 K bundles) | Retards d'ingestion par bundle | Écrire par API directe, pas par bundle ; ou option A |

## 6. Mécanisme de séparation et de nettoyage

1. Auteur dédié par origine et label `challenge:helios-fictif` sur **chaque** objet.
2. Chaque objet porte une référence externe vers le fichier source (ART-xxx) ou l'identifiant d'alerte.
3. Nettoyage possible par filtre (label ET auteur) ; la suppression requiert un accord explicite (aucune suppression sans demande).
4. Séparation de données pédagogiques et de rejeu : auteurs et labels distincts, voir 2.3.
5. Isolation technique : **option A uniquement** (ou B après levée des risques, et jamais présumée).

## 7. Contrôle après approbation (procédure, pas encore exécutée)

Après toute écriture approuvée :
1. **Relecture par API** de chaque objet et relation créés ; comparaison au manifeste (types, valeurs, étiquettes, auteurs, dates, relations).
2. **Correspondance avec les artefacts** : chaque objet renvoie à son ART/IOC/ALERT et à la ligne de journal.
3. **Liens réels** vers le rapport et l'incident (URL de la plateforme avec identifiants retournés) : fournis seulement après création.
4. **Filtres exacts** : définis après création car ils contiennent les identifiants (label, auteur, type d'entité) ; modèle prévu dans `Guide-consultation-OpenCTI.md`.
5. **Comptages réels** par rubrique, relevés dans l'interface (page par page) et par API, puis comparés aux comptages prévus (Analyses 11, Événements 9, Observations 40).
6. **Écarts et objets non ingérés** documentés (`Verification-OpenCTI.md` mise à jour).
7. **Formulation** : « objets vérifiés par API ; affichage dans l'interface non contrôlé » tant que l'interface n'a pas été ouverte rubrique par rubrique ; « visible dans les trois rubriques » seulement après ce contrôle.
8. Contrôle d'absence d'effets de bord : recherche de nouveaux objets créés par les connecteurs automatiques (enrichissement, Jira) pendant les deux cycles suivant l'écriture.

## 8. Ce qu'il faut me répondre avant toute écriture

1. **Q20** : option A (instance locale, démon Docker à démarrer, images à télécharger : taille à confirmer), B ou C ?
2. **Q21** : si B, autoriser (a) la lecture des paramètres de Google DNS, IPinfo, FIRST EPSS, du flux `jira`, des règles de déclin, (b) la désactivation temporaire de l'enrichissement automatique ?
3. **Q22** : quel compte pour écrire (compte dédié aux droits limités) ?
4. **Q23** : dates de l'incident : bornes d'observation en `first_seen`/`last_seen` avec avertissement, ou champs vides ?
5. **Q24** : accord sur les comptages et exclusions de ce plan.
