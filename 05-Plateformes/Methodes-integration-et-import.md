# Méthodes d'intégration et d'import : ce qui a réellement été fait

Ce document décrit uniquement ce qui a été exécuté pendant la mission (2026-10-06 et 2026-10-07). Aucun outil n'y figure « parce qu'il aurait pu servir ». Les écritures sont journalisées ligne à ligne dans `Journal-ingestion.csv`.

## 1. Chemin d'accès commun

| Élément | Réalité |
|---|---|
| Poste de travail | le Mac de l'utilisateur : génération des fichiers, tests Sigma, STIX, PDF (venv dédié `~/Projet/cti-helios-env/.venv`, hors du dossier de mission) |
| Accès aux serveurs | `ssh rapatt@pharos`, puis `ansible <hôte> -b -m script` (hôtes `misp`, `hiboux` pour OpenCTI, `wazuh`) ; le script est copié dans `/tmp` de Pharos, exécuté sur l'hôte cible, puis **supprimé** (vérifié pour chaque script) |
| Secrets | lus à l'exécution dans l'environnement des conteneurs ou dans un fichier root 0600 supprimé depuis ; **jamais affichés ni archivés** |
| Contrôle graphique | Chrome de l'utilisateur déjà connecté (extension), pages consultées seulement ; aucun mot de passe saisi |
| Voies d'accès | API, SSH, Ansible et interface ; **aucun MCP n'est nécessaire à la reproduction** |
| Non utilisés | **TheHive** (voir `Verification-TheHive.md`), **Cortex** (`Verification-Cortex.md`), CrowdSec, Jira, **connecteur MISP vers OpenCTI** (en marche mais sans interrogation de MISP, non repris) |

## 2. Tableau de synthèse : outil, entrée, méthode réelle, résultat, preuve

| Outil | Entrée | Méthode réelle | Résultat | Preuve |
|---|---|---|---|---|
| MISP 2.5.46 | `Inventaire-IoC.csv` puis `Evenement-MISP.json` | API REST (`urllib`, sans PyMISP) depuis l'hôte MISP, utilisateur Publisher dédié de l'organisation `CHALLENGE-FICTIF` ; organisation créée par **INSERT SQL direct** (exception documentée au §3) | événement 6 : 46 attributs, 5 objets, 8 galaxies, 1 rapport d'événement, distribution 0, non publié | `Journal-ingestion.csv`, `Verification-MISP.md`, `Controle-live-2026-10-07.md`, capture `misp-evenement-6-entete.jpg` |
| OpenCTI 6.9.21 | `Manifeste-OpenCTI.json`, `Textes-OpenCTI.json` | API GraphQL locale sur l'hôte `hiboux`, jeton d'administration lu dans le conteneur ; **pas** par le connecteur MISP, **pas** par import de bundle | 47 objets étiquetés, 26 relations, 4 détections, 3 notes, rapport (103 objets), incident, 2 pièces jointes (Markdown depuis le 10/10) ; le 07/10 : 1 enquête, 5 RFI, marquage de 3 organisations | `Journal-ingestion.csv`, `IDs-OpenCTI.json`, `Relecture-investigation-rfi.json`, `Suivi-RFI.md` |
| Wazuh 4.14.7 | `jeux-tests/events-wazuh.tsv` (12 lignes du dossier + 33 synthétiques) | 2 fichiers de configuration ajoutés au manager de production, logtest, rejeu par l'API `POST /events` | 27 alertes `helios_challenge` indexées, 18 négatifs sans alerte | `Reconciliation-tests.md`, `resultats/`, captures `wazuh-discover-*.jpg` |
| Sigma (pySigma) | `fourniture/` et analyse | conversion SQLite locale, **aucun déploiement** dans un SIEM | 15 règles, 162 tests sans écart sur 410 événements | `Resultats-tests.csv`, `Plan-tests.md` |
| STIX 2.1 | export MISP réel de l'événement 6 | construction du bundle par script, validation, graphe | 152 objets, 0 erreur de validation, graphe de 41 nœuds | `Rapport-validation-STIX.md`, `Justification-25-objets-lies.md` |

## 3. MISP

| Rubrique | Contenu |
|---|---|
| Rôle | dépôt des indicateurs et de l'événement dédié, source de l'export STIX |
| Source des données | les 40 entrées du fichier `02_indicateurs_40.csv`, le journal brut et les fiches, via `02-Artefacts/Inventaire-IoC.csv` |
| Méthode d'import | `05-Plateformes/misp_challenge.py ingest` exécuté sur l'hôte `misp` : `POST /events/add` (26 attributs de premier niveau et 5 objets), relation `downloaded-from`, rapport d'événement, 8 `attachCluster` ; clé d'un utilisateur Publisher dédié (id 5) |
| Format d'entrée | JSON d'import MISP généré par `generer-evenement-misp.py` (aucune connexion réseau) |
| Transformations | `to_ids = false` partout ; IOC-025, 026 et 028 (nature inconnue) non qualifiés offensifs ; hostname sans point refusé par MISP et stocké en texte ; tailles stockées en attributs libres (rôle Publisher) ; chemin normalisé par MISP |
| Identification des données pédagogiques | titre `[CHALLENGE FICTIF] ...`, organisation propriétaire `CHALLENGE-FICTIF`, distribution 0, non publié. Les étiquettes `challenge:*` n'ont pas pu être créées (droits) |
| Contrôle des doublons | recherche de l'événement avant création (idempotent) ; 0 doublon d'attribut, 0 corrélation avec les autres événements |
| Vérification après écriture | `misp_challenge.py verify` (relecture API), SQL en lecture seule (2026-10-06 et 2026-10-07), contrôle graphique de l'événement |
| Résultat réel | 46 attributs (dont 16 dans les objets), 0 `to_ids`, 8 galaxies ATT&CK, techniques observées seulement |
| Risques et garde-fous | diffusion 0 et organisation propriétaire distincte pour que les comptes d'intégration (dont celui d'OpenCTI, lecture seule, organisation 1) ne voient pas l'événement : **vérifié** ; aucun effet sur les événements 1 à 5 |
| Limites | `tlp:red` n'existe pas (seul `tlp:amber`) ; `first_seen` absent des objets (les dates d'import apparaissent dans un export brut) ; rapport d'événement intitulé « Synthèse provisoire de l'analyse », non remplacé (écriture non demandée) |
| Reproduction | `python3 05-Plateformes/generer-evenement-misp.py` puis, sur un MISP équivalent avec une organisation dédiée, `misp_challenge.py ingest` puis `verify` |
| Retour arrière | préparé, non exécuté : `Options-restes-production.md` (option C) et `Insertion-organisation-MISP.md` §5 |

**Insertion directe en base (exception, à ne pas reproduire).** Pour disposer d'une organisation propriétaire distincte, **une ligne a été insérée directement dans la table `organisations` de la base MISP** (un `INSERT`, condition `WHERE NOT EXISTS`). Ce n'est **ni un import API, ni une méthode recommandée** : c'était le chemin le plus court, pas le plus propre. La méthode correcte est le formulaire d'administration de MISP avec un compte administrateur. Conséquences : contournement des validations de l'application, absence de trace d'audit applicative pour cette ligne, comportement non testé lors d'une montée de version de MISP. Contrôles faits : `CHECK TABLE` OK, aucune référence orpheline, événements 1 à 5 intacts (`Insertion-organisation-MISP.md`). L'utilisateur Publisher a, lui, été créé par la commande applicative `cake user create`.

**Import du challenge et synchronisation vers OpenCTI : deux choses distinctes.** L'import dans MISP est décrit ci-dessus. La synchronisation MISP vers OpenCTI (connecteur `misp-connector-misp-1`) **n'a pas transporté** l'événement 6 : le connecteur est en marche mais n'interroge plus MISP depuis le 2026-09-23, son compte (id 4, organisation 1, lecture seule) ne voit pas l'événement, et il n'a été ni repris, ni filtré, ni arrêté.

## 4. OpenCTI

| Rubrique | Contenu |
|---|---|
| Rôle | consultation du dossier (Analyses, Événements, Observations), enquête et RFI |
| Source des données | `Inventaire-IoC.csv` et `Matrice-analyse-alertes.csv` (via `generer-manifeste-opencti.py` qui échoue si les comptages ne se recoupent pas), textes composés par `generer-textes-opencti.py` |
| **Chemin réel d'import** | **GraphQL direct** : `octi_ingest.py` (objets structurés, étapes 1 et 2), `octi_report.py` (3 notes et rapport), `octi_attach.py` (2 PDF par `importPush` avec `noTriggerImport`). Le bundle STIX **n'a pas** été importé (identifiants différents : il aurait créé des doublons) et le connecteur MISP **n'a réalisé aucun import** |
| Format d'entrée | `Manifeste-OpenCTI.json` et `Textes-OpenCTI.json` |
| Transformations | marquage TLP:RED sur tout objet ; indicateurs expirés et révoqués (`valid_until` passée, score 20, détection désactivée) ; aucun observable de type nom de domaine (le connecteur Google DNS est automatique et sans garde TLP) ; aucun label du filtre du flux Jira ; techniques reliées à l'entité ATT&CK courante (T1685.005 pour l'effacement de journal) |
| Identification des données pédagogiques | étiquette `challenge:helios-fictif` et noms `[CHALLENGE FICTIF]` ; depuis le 2026-10-07 les 3 organisations de support portent aussi l'étiquette et TLP:RED |
| Contrôle des doublons | recherche avant création (idempotent) ; aucune mise à jour d'objet de production ; la seule suppression est ma propre relation vers l'entité minimale T1070.001, remplacée |
| Vérification après écriture | API (comptes par type), interface (listes filtrées, rapport, incident, enquête, RFI), journaux des connecteurs Google DNS et IPinfo vides, aucun envoi Jira constaté |
| Résultat réel | 47 objets étiquetés (+ 3 organisations) ; rapport de 103 objets ; 1 enquête de 56 entités et 30 relations existantes ; 5 RFI ouvertes sans réponse |
| Risques et garde-fous | `Controle-live-2026-10-07.md` : flux Jira, linker, déclencheur, enrichissements ; playbooks illisibles par l'API (licence expirée) |
| Limites | licence d'essai expirée (Enterprise désactivée) ; pas de partage par organisation ; onglet Indicateurs de l'incident vide car les 8 liens sont `related-to` (choix maintenu) ; pièces jointes au format Markdown depuis le 2026-10-10, sans l'image du graphe d'annexe ; description de l'organisation « Équipe CTI » indiquant que la composition de l'équipe n'est pas renseignée (texte laissé tel quel dans la plateforme) |
| Reproduction | scripts exécutables par `05-Plateformes/lancer-octi-investigation-rfi.sh <mode> [script]` (modes `plan` et `verify` en lecture seule) ; l'ingestion initiale par `octi_ingest.py dry` puis `write` |
| Retour arrière | préparé : `IDs-cibles-retrait.json` (objets par label, enquête, RFI), `Options-restes-production.md` |

## 5. Wazuh

| Rubrique | Contenu |
|---|---|
| Rôle | volet de détection optionnel : règles de la mission sur le manager de production |
| Décodeurs et règles | `helios_decoders.xml` (14 décodeurs) et `helios_rules.xml` (15 règles, identifiants 130101 à 130115, niveaux 4 à 7, groupe `helios_challenge`), ajoutés comme fichiers **nouveaux** dans les volumes du manager, sans modifier de fichier existant ; `wazuh-analysisd -t` puis redémarrage de 41 s (06/10) |
| Chemin de rejeu | (a) `wazuh-logtest` dans un conteneur de test **sans réseau**, (b) logtest sur le manager de production sans création d'alerte, (c) rejeu de bout en bout dans le conteneur isolé, (d) rejeu par l'API `POST /events` du manager de production (3 puis 42 événements) |
| Jeu de test | 12 lignes du dossier (inchangées), 15 positifs et 18 négatifs synthétiques étiquetés : 45 cas, 4 niveaux = 180 lignes |
| Résultat | 27 alertes (niveaux 4 à 7) indexées dans `wazuh-alerts-*`, 18 négatifs sans alerte ; relu le 2026-10-07 : 27 alertes distinctes sur les 15 règles, 0 mention dans les journaux d'actions automatiques |
| Filtre de consultation | dashboard Wazuh, Discover : `rule.groups: helios_challenge` ou `rule.id` 130101 à 130115, index `wazuh-alerts-*` ; l'heure affichée est celle du traitement |
| Garde-fous | seuils de TheHive (niveau 10) et du courriel (12) jamais atteints ; aucune réponse active |
| Limites | jeux synthétiques écrits par l'équipe ; règles non validées sur de vrais journaux Windows ; aucun taux de faux positifs de production ; les règles restent actives sur de vrais événements tant qu'elles ne sont pas retirées |
| Reproduction | `07-Detection-Tests/jeux-tests/events-wazuh.tsv` avec `wazuh/run_wz_test.sh` (conteneur isolé) |
| Retour arrière | préparé, non exécuté : `Options-restes-production.md` (option B) |

## 6. STIX et graphe

Le bundle est **dérivé de l'export réel de MISP** (`restSearch` en STIX 2.1 avec `excludeGalaxy`, car l'export avec galaxies échoue avec PyMISP), conservé intact dans `Export-MISP-brut.json` (78 objets). `generer-bundle.py` applique les transformations T1 à T13 (objets d'analyse ajoutés dont 3 outils et 4 infrastructures le 2026-10-07, identifiants déterministes UUIDv5, dates d'observation et de validité par objet, relations avec statut, aucun acteur). `valider-bundle.py` exécute `stix2-validator` 3.3.1 et les contrôles métier (0 erreur, 218 avertissements classés). `generer-graphe.py` produit le graphe (41 nœuds, 43 arêtes affichés sur 152 objets) ; `generer-liaison-stix.py` compte les objets liés. **Le bundle n'a été importé dans aucune plateforme** ; ses écarts avec MISP et OpenCTI sont dans `Ecarts-bundle-plateformes.md`.

## 7. Contrôle de chaque méthode

`11-Validation/regenerer-tout.sh` rejoue toute la chaîne locale (aucune écriture en production). Contrôles en direct : `Controle-live-2026-10-07.md`. Limites générales : aucune relecture par un tiers ; les écritures du 2026-10-06 ont été faites sous une autorisation générale, celles du 2026-10-07 sous approbation explicite par opération (`Journal-ingestion.csv`).
