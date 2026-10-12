# J4 : rapports et règles Sigma

**Phase pédagogique** J4. **Date réelle** : 2026-10-06 (même jour réel que les autres phases ; revue de clôture du même jour). **Temps passé** : non connu, non renseigné. **Équipe** : non communiquée.

## Objectifs
Bundle STIX, règles Sigma et tests, rapports.

## Tâches prévues
Export et bundle STIX avec validation ; au moins 10 règles Sigma fondées sur l'analyse avec tests positifs et négatifs ; volet Wazuh optionnel ; rapports stratégique et tactique en PDF.

## Actions réellement réalisées
- **STIX** : export MISP réel (78 objets), transformé et enrichi en `Bundle-STIX.json` (152 objets après T13) ; stix2-validator (valide, 0 erreur, **218 avertissements classés après T14 (provenance des SCO)**, 101 après T13, 82 avant T13 et 126 avant la revue de clôture), stix2, stix2-patterns ; cohérence métier ; graphe généré depuis le bundle.
- **Sigma** : 15 règles (11 directes, 3 IOC, 1 chasse) ; validation pySigma ; conversion SQLite ; 410 événements, 162 tests, 0 écart.
- **Wazuh** (volet optionnel) : adaptations XML manuelles ; test en conteneur isolé (26/45 puis 45/45 en 3 passes), rejeu isolé 27 alertes ; **déploiement ciblé en production** (2 fichiers, niveaux 4 à 7, redémarrage de 41 s), rejeu limité puis complet : 27 alertes indexées, vues dans le dashboard le 2026-10-06.
- **Rapports** : stratégique (2 pages), tactique (11 pages), note d'attribution, notes ANSSI et TLP (1 page chacune), matrice CID en PDF : pagination mesurée.

## Outils et versions
Python 3.14.7, pandoc 3.11, jq, shasum ; venv dédié (stix2 3.0.2, stix2-validator 3.3.1, pySigma 1.5.1, pySigma-backend-sqlite 2.0.0, networkx 3.7, matplotlib 3.11.2, PyMuPDF 1.28.2) ; Wazuh 4.14.7 (manager de production, conteneur de test `wazuh/wazuh-manager:4.14.7` supprimé) ; Chrome headless pour le rendu PDF.

## Artefacts traités
Export MISP de l'événement 6 ; 12 lignes de journal rejouables et 33 événements de test écrits par l'équipe ; analyses de J2 et J3.

## Résultats
Bundle valide ; 15 règles sans écart sur les jeux de test ; 27 alertes Wazuh réellement produites ; 5 PDF de rapport. Réconciliation des chiffres : `07-Detection-Tests/Reconciliation-tests.md`.

## Preuves
`06-STIX-Graphe/Rapport-validation-sortie.txt`, `07-Detection-Tests/Resultats-tests.csv`, `07-Detection-Tests/Resultats-wazuh.csv`, `07-Detection-Tests/resultats/`, `11-Validation/Pages-PDF.csv`, `11-Validation/preuves-consultation/wazuh-discover-27-alertes.jpg`.

## Décisions et difficultés
DEC-016 à DEC-025 ; niveaux de règles Wazuh abaissés pour rester sous les seuils d'automatisation. Difficultés : validateur STIX sans schémas (défaut d'installation) ; décodeurs Wazuh (champs statiques, décodeurs enfants, OS_Regex) ; export MISP STIX en erreur avec galaxies.

## Reste à faire
Aucune tâche restante pour cette phase. Limites définitives : règles Wazuh de production maintenues, non validées sur de vrais journaux ; aucune mesure de taux de faux positifs en production (limites définitives).

## Contrôles effectués
`07-Detection-Tests/Plan-tests.md` (7 niveaux, tous exécutés dont le dashboard le 2026-10-06) ; `controle-coherence.py` ; `controles-exigences.py`.
