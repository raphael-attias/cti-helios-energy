# J1 : cadrage et triage

**Phase pédagogique** J1. **Date réelle** : 2026-10-06 (toutes les phases ont eu lieu le même jour réel ; aucune journée passée n'est inventée). **Temps passé** : non connu, non renseigné. **Équipe** : non communiquée.

## Objectifs
Vérifier accès et outils, inventorier sans modifier, ouvrir le pilotage, produire la note de cadrage.

## Tâches prévues
Découverte, inventaires IoC/alertes/binaires, intégrité, registre des sources, matrice d'exigences, note de cadrage (2 pages, **échéance fin J1**), planning, rôles.

## Actions réellement réalisées
1. Inventaire des 7 fichiers de `fourniture/` ; sha256 relus avant et après chaque phase (**originaux inchangés**).
2. Génération par script des inventaires (`02-Artefacts/`), 3 contrôles automatiques de cohérence.
3. Vérification en lecture des accès : MISP, OpenCTI, Wazuh (Cortex et CrowdSec constatés non utilisés) (`00-Pilotage/Inventaire-infrastructure.md`).
4. Intégrité et provenance : 17 constats, portés à 21 lors de l'analyse des alertes.
5. Matrice d'exigences, journal de décisions, registre des blocages, questions au commanditaire.
6. **Note de cadrage : produite le 2026-10-06 après l'échéance de fin J1 : elle n'a pas été remise à temps.** Version finale : 2 pages mesurées après génération du PDF.

## Outils et versions
Python 3.14.7, pandoc 3.11, jq, shasum ; venv dédié (stix2 3.0.2, stix2-validator 3.3.1, pySigma 1.5.1, pySigma-backend-sqlite 2.0.0, networkx 3.7, matplotlib 3.11.2, PyMuPDF 1.28.2) ; MISP 2.5.46 ; OpenCTI 6.9.21 ; Wazuh 4.14.7 (outils réellement utilisés ; ni Cortex ni TheHive).

## Résultats
Lot conforme en nombre mais **3 fiches et 0 échantillon** ; aucun doublon ni valeur invalide ; 21 incohérences documentées.

## Preuves
`02-Artefacts/sortie-generer-inventaires.txt`, `Inventaire-*.csv`, `Integrite-et-provenance.md`, `01-Cadrage/Note-cadrage.pdf`.

## Décisions et difficultés
DEC-001 à DEC-009 (`Journal-decisions.md`). Difficultés : échantillons absents ; clé MISP non fournie au départ ; API Wazuh injoignable depuis le Mac.

## Reste à faire
Aucune tâche restante pour cette phase. Limites définitives : rôles réels et temps passé non communiqués : limite définitive (rien n'est inventé).

## Contrôles effectués
sha256 des originaux ; CSV contre JSON ; empreintes fiches contre CSV ; alertes contre journal ; pagination de la note de cadrage.
