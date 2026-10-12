# J2 : corrélation et enrichissement MISP

**Phase pédagogique** J2. **Date réelle** : 2026-10-06 (même jour réel que les autres phases ; revue de clôture du même jour). **Temps passé** : non connu, non renseigné. **Équipe** : non communiquée.

## Objectifs
Corréler et enrichir les IoC, structurer le renseignement dans MISP, analyser les alertes.

## Tâches prévues
Analyse indépendante des 12 alertes ; analyse des 40 IoC ; enrichissement par sources ouvertes ; corrélations ; ingestion MISP ; constat d'absence d'usage de Cortex (voir `05-Plateformes/Verification-Cortex.md`).

## Actions réellement réalisées
1. Analyse indépendante des 12 alertes (`04-Analyse/Matrice-analyse-alertes.csv`, 22 colonnes, 29 preuves relues automatiquement) ; chronologie (34 événements) ; matrice ATT&CK vérifiée sur attack.mitre.org.
2. Analyse des 40 IoC (`Analyse-IoC.md`) avec cotes Admiralty de l'équipe ; indicateurs extraits (15).
3. **Enrichissement par sources ouvertes** : uniquement documentation officielle (ATT&CK, ANSSI, CNIL, FIRST) ; aucune valeur d'IoC envoyée à un tiers (`03-Sources/Journal-collecte.csv`).
4. Corrélations : toutes de nature décrite (égalité exacte, lien temporel, relation déclarée) ; MISP et OpenCTI : 0 corrélation externe.
5. **Ingestion MISP** (production, organisation dédiée CHALLENGE-FICTIF créée par INSERT SQL, distribution 0, non publié) : événement 6, 46 attributs, 5 objets, 8 galaxies observées ; relecture par API (`Verification-MISP.md`, `Journal-ingestion.csv`). Détail de l'insertion et retour arrière : `00-Pilotage/Insertion-organisation-MISP.md`.
6. Cortex : **non utilisé** (aucun job pour la mission ; analyseurs tiers non approuvés ; constat en lecture seule dans `Verification-Cortex.md`) ; TheHive non utilisé non plus (`Verification-TheHive.md`).

## Outils et versions
Python 3.14.7, pandoc 3.11, jq, shasum ; venv dédié (stix2 3.0.2, stix2-validator 3.3.1, pySigma 1.5.1, pySigma-backend-sqlite 2.0.0, networkx 3.7, matplotlib 3.11.2, PyMuPDF 1.28.2) ; MISP 2.5.46 (API REST, cake, MySQL en lecture) ; OpenCTI 6.9.21 (outils réellement utilisés : MISP, OpenCTI, Wazuh ; ni Cortex ni TheHive).

## Artefacts traités
Les 7 fichiers de `fourniture/` ; 40 IoC (IOC-001 à IOC-040), 12 alertes (ALERT-001 à ALERT-012), 3 fiches (BIN-001 à BIN-003), journal brut (12 lignes de journal plus 360 lignes de bruit).

## Résultats
Événement MISP 6 relu (46 attributs dont 5 objets, 8 galaxies, 0 `to_ids`, 0 doublon, 0 corrélation). Écarts : hostname refusé, tailles et chemin transformés, étiquettes personnalisées non créées (droits), export STIX avec galaxies en erreur.

## Preuves
`04-Analyse/Matrice-analyse-alertes.csv`, `04-Analyse/Chronologie.csv`, `05-Plateformes/Evenement-MISP.json`, `05-Plateformes/Verification-MISP.md`, `05-Plateformes/Journal-ingestion.csv`, `11-Validation/preuves-consultation/misp-evenement-6-entete.jpg`.

## Décisions et difficultés
DEC-010 à DEC-025 (`00-Pilotage/Journal-decisions.md`). Isolation MISP par organisation propriétaire distincte ; connecteur MISP vers OpenCTI en marche mais sans interrogation de MISP avant la mission (file de 227 K bundles), sans filtre. Difficultés : droits Publisher limités, hostname sans point refusé.

## Reste à faire
Aucune tâche restante pour cette phase. Limites définitives : connecteur MISP vers OpenCTI ni filtré ni repris, objets de test maintenus : arbitrages non obtenus, procédures préparées (`00-Pilotage/Options-restes-production.md`, `Decisions-et-limites-finales.md`).

## Contrôles effectués
Relecture complète de l'événement par API et comparaison au manifeste ; consultation de l'interface MISP et lecture SQL des tables le 2026-10-06 (revue de clôture).
