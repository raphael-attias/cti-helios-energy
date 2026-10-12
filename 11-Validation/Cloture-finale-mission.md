# Clôture finale de la mission : Challenge CTI Helios Energy (INC-2026-0302)

Date : 2026-10-07. Investigation CTI sur l'attaquant d'une intrusion fictive chez Helios Energy (statut d'opérateur d'importance vitale fourni par l'énoncé). Les chiffres de ce document sont ceux de `Audit-final-criteres.md` et de `00-Pilotage/Tableau-de-bord.md`, générés depuis la matrice des critères. **Aucune exigence n'a été relue ni validée par le commanditaire** : tout statut ci-dessous est un contrôle technique de l'équipe.

## 1. Résumé final

- **Couverture vérifiée : 33 exigences officielles sur 36 sont satisfaites et contrôlées (91,7 %).** 1 est partielle (REQ-07, livrée après l'échéance), 2 non satisfaites (REQ-04 faute d'échantillons, REQ-36 faute d'approbation du dépôt). REQ-15 (25 objets liés) est satisfaite sous une méthode conservatrice propre à l'équipe : **27 objets de renseignement liés**, dont 7 ajoutés le 2026-10-07 sur preuve du journal brut ou des alertes. Aucun « partiel » n'a été converti en « satisfait » pour atteindre un pourcentage.
- Conclusion d'attribution : **cluster non attribué**, aucun acteur nommé ; la piste du LISEZ-MOI est traitée comme une indication, pas comme une preuve.
- Plateformes : événement MISP, rapport OpenCTI (103 objets), enquête en vue synthétique, 5 RFI, règles Wazuh (27 alertes), tous relus par API et dans l'interface. Une relecture critique des livrables a corrigé 21 défauts (`Relecture-finale.md`) ; elle n'est ni indépendante ni une validation du commanditaire.
- **TheHive et Cortex n'ont pas été utilisés** : vérifié en lecture seule.
- Le **dépôt Git n'est pas créé** : sa création n'a pas été approuvée.

## 2. Livrables disponibles

| Livrable final | Emplacement | État |
|---|---|---|
| Note de cadrage (2 pages) | `01-Cadrage/Note-cadrage.pdf` | produite après l'échéance « fin J1 » (limite déclarée) |
| Planning 35 h, rôles et communication | `01-Cadrage/` | rôles « non communiqués » |
| Inventaires (40 IoC, 12 alertes, 3 fiches), intégrité, sources | `02-Artefacts/`, `03-Sources/` | originaux intacts (sha256 identiques) |
| Analyse des IoC, des 12 alertes, des fiches binaires, chronologie | `04-Analyse/` | les fiches ne sont **pas** des échantillons analysés |
| ATT&CK (v19.2 avec correspondance v18.1), Diamond, attribution, cartographie SI, matrice CID | `04-Analyse/` | cluster non attribué |
| Bundle STIX 2.1 (152 objets), graphe (41 nœuds), validation, justification des 25 objets liés | `06-STIX-Graphe/` | 0 erreur de validation, 218 avertissements classés |
| 15 règles Sigma, adaptations Wazuh, tests | `07-Detection-Tests/` | voir §5 |
| Rapport stratégique (2 p.), rapport tactique (11 p.) | `08-Rapports/` | PDF régénérés le 2026-10-07 |
| Notes : attribution (2 p.), ANSSI (1 p.), partage TLP (1 p.) | `08-Rapports/` | OIV fourni, SIIV et secteur inconnus |
| Journaux J1 à J5 | `09-Journal-mission/` | un seul jour réel (2026-10-06), dates réelles conservées |
| Soutenance : plan, support (15 diapositives), préparation aux questions (2 p.) | `10-Soutenance/` | non répétée |
| Méthodes d'intégration et d'import | `05-Plateformes/Methodes-integration-et-import.md` | décrit ce qui a réellement été fait |
| Vérifications TheHive et Cortex | `05-Plateformes/Verification-TheHive.md`, `Verification-Cortex.md` | non utilisés |
| Investigation OpenCTI finale, relecture finale | `05-Plateformes/Investigation-OpenCTI-finale.md`, `11-Validation/Relecture-finale.md` | vue synthétique ; relecture par l'auteur |
| Matrice finale, audit, décisions et limites, suivi des RFI | `11-Validation/Audit-final-criteres.md`, `00-Pilotage/` | générés ou rédigés le 2026-10-07 |
| Manifeste avec hashes, captures de consultation | `11-Validation/Manifest-livrables.csv`, `preuves-consultation/` | manifeste vérifié sans écart |
| Historique (registres de questions et de blocages, plans, revue du 06/10) | `99-Historique/` | **non final**, conservé comme preuve |

PDF (pages comptées par script) : cadrage 2, stratégique 2, tactique 11, attribution 2, ANSSI 1, partage 1, questions de soutenance 2, matrice CID 2, support de soutenance 15.

## 3. Couverture réelle des critères

| Périmètre | Total | Satisfait et contrôlé | Partiel | Non satisfait | Non applicable |
|---|---|---|---|---|---|
| Exigences officielles (liste non confirmée par le commanditaire) | 36 | **33** | 1 | 2 | 0 |
| Volet Wazuh optionnel (OPT-03) | 1 | 1 | 0 | 0 | 0 |
| Autres optionnels (OPT-01 correspondance, 02 Cortex, 04 CrowdSec, 05 dark web) | 4 | 1 (dark web, consultation indirecte) | 1 | 0 | 2 |
| Demandes OpenCTI supplémentaires (consultation, enquête, RFI) | 3 | 2 (consultation, RFI) | 1 (enquête : lisibilité limitée) | 0 | 0 |

| Exigence | Statut | Limite précise |
|---|---|---|
| REQ-04 analyse des binaires | NON SATISFAIT | échantillons non fournis (imputable au dossier) ; RFI-01 ouverte |
| REQ-36 dépôt Git | NON SATISFAIT | création non approuvée ; procédure prête |
| REQ-07 note de cadrage | PARTIEL | livrée après l'échéance de fin de J1 |

Une RFI créée prouve un suivi, **pas** l'obtention de l'information : les 5 RFI restent ouvertes, sans réponse, et l'information manquante est une limite finale.

## 4. Méthodes d'intégration et d'import (synthèse)

MISP : API REST depuis l'hôte, utilisateur Publisher dédié ; organisation créée par **INSERT SQL direct** (exception documentée, non recommandée). OpenCTI : **API GraphQL**, ni connecteur MISP ni import du bundle. Wazuh : 2 fichiers de configuration ajoutés, logtest isolé puis rejeu par l'API. STIX : dérivé de l'export MISP, non importé. Détail, preuves et reproduction : `05-Plateformes/Methodes-integration-et-import.md`.

## 5. Résultats des tests

| Niveau | Résultat | Preuve |
|---|---|---|
| Sigma : validation syntaxique | 15 règles valides | `07-Detection-Tests/resultats/` |
| Sigma : tests locaux (SQLite) | 162 couples règle × événement sur 410 événements : 0 écart, 0 faux positif | `Resultats-tests.csv` |
| Wazuh : logtest | 45 cas sur 45 conformes (isolé et production) ; 180 lignes = 45 cas × 4 niveaux | `Resultats-wazuh.csv` |
| Wazuh : rejeu | 27 positifs donnent 27 alertes, 18 négatifs donnent 0 ; 27 alertes indexées et relues le 2026-10-07 | `resultats/`, `Controle-live-2026-10-07.md` |
| STIX | valide, 0 erreur, 218 avertissements classés | `Rapport-validation-STIX.md` |
| Cohérence du dossier | 42 contrôles dont 0 écart ; contrôles par exigence : voir `Controles-exigences.csv` | `controle-coherence-sortie.txt` |

Limites : jeux synthétiques écrits par l'équipe, aucun taux de faux positifs de production, règles non validées sur de vrais journaux Windows. Les comptages 162, 410, 45, 180, 27 et 18 sont réconciliés dans `07-Detection-Tests/Reconciliation-tests.md`.

## 6. État final des plateformes et changements conservés

| Plateforme | Changements conservés | Retour arrière |
|---|---|---|
| MISP 2.5.46 | organisation 2 `CHALLENGE-FICTIF` (insérée en SQL), utilisateur 5, événement 6 (46 attributs, 5 objets, 8 galaxies, non publié) | préparé, non exécuté (`Options-restes-production.md`, `Insertion-organisation-MISP.md`) |
| OpenCTI 6.9.21 | 47 objets d'origine, 3 organisations (étiquette et TLP:RED depuis le 07/10), rapport de 103 objets (dont 4 infrastructures, 1 outil et 11 relations ajoutés le 07/10), incident, 2 pièces jointes **remplacées le 10/10 par les versions Markdown des rapports** (PDF finaux du 07/10 archivés dans `99-Historique/`), 1 enquête (vue synthétique), 5 RFI | `IDs-cibles-retrait.json` |
| Wazuh 4.14.7 | `helios_decoders.xml`, `helios_rules.xml` (130101 à 130115), 27 alertes | préparé, non exécuté |

Services : connecteur MISP vers OpenCTI en marche mais n'interrogeant pas MISP, **non repris, non filtré** ; aucun redémarrage de contrôle ; aucune réponse active, aucun envoi Jira ni TheHive, aucun blocage CrowdSec. Wazuh : 11 démons en marche sur 15, les 4 arrêtés sont désactivés par la configuration. Écritures du 2026-10-07 faites après approbation explicite : enquête et sa vue synthétique, 5 RFI et la mise à jour du texte de la RFI-05, marquage de 3 organisations, compléments STIX (4 infrastructures, 1 outil, 11 relations), remplacement des 2 PDF joints par des versions Markdown le 2026-10-10 (`Journal-ingestion.csv`). Contrôle de cohérence final des plateformes (lecture seule) : OpenCTI 103 objets au rapport, 4 infrastructures, 5 RFI, 3 enquêtes dont la nôtre ; MISP événement 6 intact (46 attributs, 5 objets, 0 corrélation) ; Wazuh 27 alertes, 0 réponse active.

## 7. Explication TheHive

**Je ne vois rien dans TheHive parce que TheHive n'a pas été utilisé pour cette mission : aucun case, alerte ou observable Helios n'y a été créé ni importé, et aucun chemin automatique n'aurait dû en créer.** Preuves en lecture seule : une seule organisation, 122 cases, 70 397 alertes et 251 661 observables, dont 0 contenant Helios, INC-2026-0302 ou les 6 valeurs du dossier testées ; la même recherche par API renvoie 0 et un contrôle positif fonctionne ; aucun case clos ne masque de résultat ; les chemins Wazuh (niveau 10), MISP (étiquette `thehive:import` absente de l'événement 6) et OpenCTI (sens unique vers OpenCTI) ne transportent rien. La licence invalide explique le bandeau, pas l'absence (93 alertes y ont été créées le 07/10). Incertitude : l'organisation sélectionnée dans la capture n'est pas visible ; Elasticsearch n'a pas été lu directement. Détail : `05-Plateformes/Verification-TheHive.md`.

## 8. Contribution Cortex

**Aucune.** Le journal d'accès de Cortex (2026-09-19 à 2026-10-07) ne montre aucun lancement d'analyseur du 1er au 7 octobre (478 lancements du 19 au 30 septembre, issus de TheHive (433), de l'hôte OpenCTI (39) et de Pharos (6), donc antérieurs à la mission) ; aucune valeur du dossier n'existe côté TheHive. Cortex n'est cité ni comme outil ni comme source d'enrichissement. Constat technique uniquement dans `05-Plateformes/Verification-Cortex.md`.

## 9. Limites définitives

Aucun échantillon binaire ; une seule ligne de balise ; journal Security effacé ; 6 incohérences du dossier non levées (RFI-02) ; aucune source indépendante pour l'attribution (RFI-04) ; SIIV, secteur et contenu des 2,47 Go inconnus (RFI-03) ; équipe et temps non communiqués ; définition des « objets liés » non fournie (RFI-05 ; REQ-15 satisfaite sous la méthode de l'équipe seulement) ; liste des exigences non confirmée (sujet officiel absent) ; objets pédagogiques et règles Wazuh maintenus (retraits non demandés) ; TLP AMBER (MISP) contre RED (OpenCTI) ; enquête OpenCTI lisible seulement forces désactivées ; ajouts STIX absents de MISP ; relations indicateur vers incident maintenues en `related-to` ; aucun taux de faux positifs de production ; NIS 2 vérifié sur des sources secondaires ; aucune relecture par un tiers. Registre complet : `00-Pilotage/Decisions-et-limites-finales.md`.

## 10. Emplacement et état du dépôt Git

Emplacement prévu : `/Users/rapatt/Projet/cti-helios-energy` (local, branche `main`, sans remote). **État : absent.** Le dépôt est obligatoire depuis le sujet initial ; sa création a été soumise à approbation le 2026-10-07 (trois demandes) et n'a pas été approuvée. La copie, la vérification, `git init` et le commit local sont prêts (`11-Validation/preparer-depot-git.sh`, manifeste `Depot-Git-manifeste.csv` sans `*.bak`, binaire ni secret, essai à blanc exécuté). Tant qu'il n'existe pas, REQ-36 reste NON SATISFAIT.
