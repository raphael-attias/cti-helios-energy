# J5 : réglementation, partage, graphe, soutenance

**Phase pédagogique** J5. **Date réelle** : 2026-10-06 (même jour réel que les autres phases ; revue de clôture du même jour). **Temps passé** : non connu, non renseigné. **Équipe** : non communiquée.

## Objectifs
Notes réglementaire et de partage, graphe, soutenance, contrôle final.

## Tâches prévues
Note ANSSI (1 page) ; note de partage TLP (1 page) ; graphe CTI depuis le bundle ; support de soutenance (20 min) et questions (10 min) ; contrôle final.

## Actions réellement réalisées
- Notes ANSSI et TLP après lecture des sources officielles du jour (ANSSI, CNIL, FIRST) ; **aucune déclaration réelle**, aucun partage ; l'article L1332-6-2 sur Légifrance n'a pas pu être lu directement.
- OpenCTI en trois rubriques (rapport et notes ; incident, données observées, détections ; observables et indicateurs) sur l'infrastructure existante après levée des risques (enrichissement automatique, flux Jira, connecteur MISP) ; relecture par API ; PDF rattachés au rapport sans déclencher l'import automatique.
- Soutenance : plan, support de 15 diapositives (durée indicative 20 min), 18 questions préparées.
- Contrôle final, couverture des 8 compétences, manifeste des livrables avec hashes, bilan de session, **revue de clôture** (interfaces MISP, OpenCTI, Wazuh consultées le 2026-10-06).

## Outils et versions
Python 3.14.7, pandoc 3.11, jq, shasum ; venv dédié (stix2 3.0.2, stix2-validator 3.3.1, pySigma 1.5.1, pySigma-backend-sqlite 2.0.0, networkx 3.7, matplotlib 3.11.2, PyMuPDF 1.28.2) ; Chrome (session de l'utilisateur) pour le contrôle des interfaces ; OpenCTI 6.9.21 ; MISP 2.5.46 ; Wazuh 4.14.7.

## Artefacts traités
Bundle corrigé, graphe, analyses, rapports ; sources réglementaires en ligne.

## Résultats
Notes d'une page chacune, support de 15 diapositives, graphe régénéré depuis le bundle corrigé, contrôles d'interface avec réserves (voir `99-Historique/Revue-cloture.md` et `05-Plateformes/Diagnostic-OpenCTI.md`).

## Preuves
`08-Rapports/Note-reglementaire-ANSSI.pdf`, `08-Rapports/Note-partage-communautaire.pdf`, `10-Soutenance/Support-soutenance.pdf`, `06-STIX-Graphe/Graphe-CTI.png`, `11-Validation/preuves-consultation/`.

## Décisions et difficultés
Aucune déclaration ni partage sans accord ; statut OIV fourni par l'énoncé (SIIV et secteur inconnus). Difficultés : certificat MISP auto-signé (identité vérifiée par empreinte), graphe de l'incident OpenCTI non rendu.

## Reste à faire
Aucune tâche restante pour cette phase. Limites définitives : état final et limites : `11-Validation/Cloture-finale-mission.md` ; historique de la revue du 2026-10-06 : `99-Historique/Revue-cloture.md`.

## Contrôles effectués
`11-Validation/Controle-final.md` et sa sortie `controle-coherence-sortie.txt` ; `11-Validation/Controles-exigences.csv`.
