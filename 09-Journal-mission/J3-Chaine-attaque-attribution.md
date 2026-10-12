# J3 : chaîne d'attaque et attribution

**Phase pédagogique** J3. **Date réelle** : 2026-10-06 (même jour réel que les autres phases ; revue de clôture du même jour). **Temps passé** : non connu, non renseigné. **Équipe** : non communiquée.

## Objectifs
Matrice ATT&CK, Diamond Model, attribution et Admiralty, impact sur les actifs, cartographie SI.

## Tâches prévues
Rattacher les techniques observées à ATT&CK avec source officielle ; Diamond Model ; comparer les hypothèses d'attribution ; matrice CID ; cartographie du SI connu ; analyse statique des fiches binaires.

## Actions réellement réalisées
- ATT&CK : 8 techniques OBSERVÉES vérifiées sur la source officielle ; 2 techniques du SIEM écartées (T1055.012, T1543.003) ; **T1070.001 renuméroté T1685.005 en v19** (trouvé grâce au validateur pySigma puis confirmé sur attack.mitre.org). Méthode ATT&CK de la revue de clôture : `04-Analyse/Version-ATTACK.md`.
- Diamond Model (`Diamond-Model.md`), hypothèses et attribution (`Hypotheses-et-attribution.md`) : **cluster non attribué**, confiance élevée dans cette conclusion ; indication du LISEZ-MOI écartée de la chaîne de preuve.
- Cartographie du SI connu avec inconnues visibles ; matrice CID (5 actifs, observé / potentiel / futur) ; échelle justifiée.
- Fiches binaires : « analyse des fiches fournies » (aucun hash recalculé, aucun échantillon).

## Outils et versions
Python 3.14.7, pandoc 3.11, jq, shasum ; venv dédié (stix2 3.0.2, stix2-validator 3.3.1, pySigma 1.5.1, pySigma-backend-sqlite 2.0.0, networkx 3.7, matplotlib 3.11.2, PyMuPDF 1.28.2) ; pages officielles attack.mitre.org (v19, publiée le 28 avril 2026).

## Artefacts traités
12 alertes, 3 fiches BIN, journal brut, mémo SOC, 40 IoC.

## Résultats
`Note-attribution.md` (cluster non attribué), `Matrice-risques-CID.pdf` (5 actifs), `Cartographie-SI.md`, `Matrice-ATTACK.csv` (18 lignes dont 8 techniques OBSERVÉES).

## Preuves
`04-Analyse/Matrice-ATTACK.csv`, `04-Analyse/Diamond-Model.md`, `04-Analyse/Hypotheses-et-attribution.md`, `08-Rapports/Note-attribution.pdf`, `11-Validation/Controles-exigences.csv`.

## Décisions et difficultés
Décisions sur les points fragiles (alerte 9, alerte 8, parent winword.exe/.xlsm, IP pseudonymisées, références IP des fiches non résolues). Difficultés : absence d'échantillons ; une seule ligne de balise ; chronologie contradictoire (compte utilisé 36 h avant sa création).

## Reste à faire
Aucune tâche restante pour cette phase. Limites définitives : informations manquantes : RFI-01 à RFI-04 ouvertes dans OpenCTI, sans réponse (limites définitives) ; cotations Admiralty non relues par un tiers.

## Contrôles effectués
Chaque conclusion : observation, preuve, interprétation, confiance, limite ; 29 extraits relus automatiquement dans les originaux ; contrôles techniques de la revue de clôture (`controles-exigences.py`).
