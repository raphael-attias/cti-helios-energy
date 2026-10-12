# Plan de soutenance (20 minutes + 10 minutes de questions)

Support : `Support-soutenance.pdf` (15 diapositives, durées indicatives totalisant 20 minutes). Préparation aux questions : `Questions-reponses.md`. Intervenants : non communiqués (équipe non fournie).

| # | Diapositive | Durée | Message à faire passer | Pièce de preuve |
|---|---|---|---|---|
| 1 | Titre et cadre | 1 | exercice fictif ; principe OBSERVÉ / HYPOTHÈSE / INCONNU | README |
| 2 | Mission et dossier | 1 | 3 fiches, 0 échantillon | `Inventaire-*.csv` |
| 3 | Méthode et garde-fous | 1 | preuves relues, aucun IoC envoyé à un tiers | `Controle-coherence-sources.csv` |
| 4 | 21 incohérences | 1 | ne pas corriger, documenter les lectures | `Integrite-et-provenance.md` |
| 5 | Chronologie | 1 | bornes d'observation, pas début et fin | `Chronologie.csv` ; version présentable : `04-Analyse/Timeline-incident.md` (frise et tableau ATT&CK, aussi en tête de `Resume-prez-doc.md`) |
| 6 | 12 alertes | 3 | alerte 8, alerte 9, T1685.005 | `Matrice-analyse-alertes.csv` |
| 7 | Fiches binaires | 1 | capacité supposée contre comportement observé | `Analyse-binaires.md` |
| 8 | Graphe | 1 | hypothèses visibles | `Graphe-CTI.png` |
| 9 | Attribution | 2 | cluster non attribué, piste du LISEZ-MOI non probante | `Note-attribution.md` |
| 10 | Plateformes | 2 | ce qui est vérifié par API, ce qui ne l'est pas | `Verification-*.md` |
| 11 | Détection | 2 | 7 niveaux de test distincts | `Plan-tests.md` |
| 12 | Rejeu en production | 1 | précautions et retour arrière | `Journal-ingestion.csv` |
| 13 | Impact et recommandations | 1 | observé, potentiel, futur | `Matrice-risques-CID.csv` |
| 14 | Réglementation et partage | 1 | OIV, NIS 2, RGPD distincts | notes 1 page |
| 15 | Limites | 1 | ce qui manque | `99-Historique/Bilan-final-session.md` |

Démonstrations possibles (si les interfaces sont accessibles au jury) : OpenCTI, rubriques Analyses / Événements / Observations avec le filtre du guide ; MISP, événement 6 ; Wazuh, filtre `rule.groups: helios_challenge`. **Aucune de ces vues n'a été contrôlée graphiquement par l'équipe** : à vérifier avant la soutenance.
