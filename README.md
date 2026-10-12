# Challenge CTI Helios Energy : dossier final

Investigation CTI sur l'attaquant de l'incident INC-2026-0302 (victime fictive : Helios Energy). Tout est tracé depuis les artefacts de `fourniture/` (originaux jamais modifiés). **Commencer par `11-Validation/Cloture-finale-mission.md`.** La mission n'est pas validée à 100 % : 33 exigences officielles sur 36 sont satisfaites et contrôlées, 1 partielle, 2 non satisfaites (détail dans la clôture). Aucune validation du commanditaire n'est revendiquée.

## Où trouver quoi

| Dossier | Nature | Contenu |
|---|---|---|
| `fourniture/` | sources originales (lecture seule) | 7 fichiers d'origine : 40 IoC, 12 alertes, 3 fiches de binaires (sans échantillon), mémo, journal brut |
| `01-Cadrage/` | **livrable final** | note de cadrage (PDF 2 p., remise après l'échéance de fin de J1), planning, rôles |
| `02-Artefacts/`, `03-Sources/` | livrables et preuves | inventaires, intégrité, registre des sources, journal de collecte |
| `04-Analyse/` | **livrable final** | analyses IoC, alertes et fiches, chronologie, ATT&CK, Diamond, attribution (cluster non attribué), cartographie, matrice CID |
| `05-Plateformes/` | livrables, preuves, scripts | **méthodes d'intégration et d'import**, **investigation OpenCTI finale**, vérifications MISP, OpenCTI, TheHive, Cortex, guide de consultation, journaux et scripts d'ingestion |
| `06-STIX-Graphe/` | livrable et preuves | bundle STIX 2.1, graphe et script, validation, justification des 25 objets liés, écarts avec les plateformes |
| `07-Detection-Tests/` | livrable et preuves | 15 règles Sigma, adaptations Wazuh, tests et réconciliation |
| `08-Rapports/` | **livrables finaux (PDF)** | rapports stratégique et tactique, notes d'attribution, ANSSI et partage TLP |
| `09-Journal-mission/` | livrable final | journaux J1 à J5 (phases pédagogiques, dates réelles) |
| `10-Soutenance/` | livrable final | **`Resume-prez-doc.md` (fil conducteur de la présentation : l'essentiel de chaque point + lien vers le document complet)**, plan, support (15 diapositives), préparation aux questions |
| `00-Pilotage/` | pilotage final | tableau de bord, matrice des critères, décisions et limites finales, suivi des RFI, restes en production |
| `11-Validation/` | clôture, preuves, scripts de contrôle | `Cloture-finale-mission.md`, `Audit-final-criteres.md`, `Relecture-finale.md`, contrôles live, manifeste avec hashes, captures |
| `99-Historique/` | historique, **non final** | registres de questions et de blocages, plans, revue du 2026-10-06, anciennes matrices |

Reprise par un agent : `AGENTS.md`.

## Reproduire

- Tout régénérer en local (aucune écriture en production) : `bash 11-Validation/regenerer-tout.sh` (venv dédié `/Users/rapatt/Projet/cti-helios-env/.venv`).
- Chaîne STIX seule : `bash 11-Validation/regenerer-stix.sh` ; tests Sigma : `07-Detection-Tests/tester-sigma.py` ; PDF : `11-Validation/generer-pdf.py <fichier.md>`.
- Plateformes (lecture seule) : `bash 05-Plateformes/lancer-octi-investigation-rfi.sh plan|verify` ; procédures complètes dans `05-Plateformes/Methodes-integration-et-import.md`.
- Les statuts ne se modifient pas à la main : éditer `11-Validation/maj-matrice.py`.

Règles : pas de binaire, de secret ni de clé dans ce dossier ; toute écriture dans une plateforme est journalisée dans `05-Plateformes/Journal-ingestion.csv`.
