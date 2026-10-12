# Tableau de bord

Clôture du 2026-10-07. Compteurs **calculés par script** (`11-Validation/generer-tableau-de-bord.py`) sur `Matrice-exigences.csv`. **La mission n'est pas validée à 100 %.** Détail et preuves : `11-Validation/Cloture-finale-mission.md` et `11-Validation/Audit-final-criteres.md` ; origine des exigences : `00-Pilotage/Exigences-origine.md` ; limites et arbitrages : `00-Pilotage/Decisions-et-limites-finales.md`.

## Trois périmètres, trois couvertures (jamais mélangés)

| Périmètre | Total | SATISFAIT ET CONTRÔLÉ | PARTIEL | NON SATISFAIT | NON APPLICABLE | Couverture |
|---|---|---|---|---|---|---|
| **Exigences officielles** (lecture du brief ; liste non confirmée par le commanditaire) | 36 | 33 | 1 | 2 | 0 | **33 / 36 (91.7 %)** |
| **Volet Wazuh optionnel** (OPT-03) | 1 | 1 | 0 | 0 | 0 | hors dénominateur |
| **Autres optionnels** (OPT-01, 02, 04, 05) | 4 | 1 | 1 | 0 | 2 | hors dénominateur |
| **Demandes supplémentaires OpenCTI** (consultation, investigation, RFI) | 3 | 2 | 1 | 0 | 0 | 2 / 3 |

**Sens des statuts** : SATISFAIT ET CONTRÔLÉ = livrable existant, contenu présent, preuve traçable, contrôle exécuté, limites écrites. PARTIEL = livré avec une limite précise qui empêche de conclure au satisfait. NON SATISFAIT = non livrable, avec sa cause. NON APPLICABLE = hors sujet, avec sa justification. **Aucun statut n'est une validation par le commanditaire** : celle-ci vaut **0 / 36**. Aucun « partiel » n'a été converti en « satisfait » pour atteindre un pourcentage.

## Quatre niveaux distincts (36 exigences officielles)

| Niveau | Oui | Partiel | Non |
|---|---|---|---|
| Déclaré réalisé | 34 | 1 | 1 |
| Preuve archivée | 35 | 0 | 1 |
| Contrôle exécuté (niveau déclaré) | 34 | 1 | 1 |
| Satisfait et contrôlé (critères ci-dessus) | 33 | 0 | 3 |
| Relu par l'utilisateur ou validé par le commanditaire | 0 | 0 | 36 |

## Ce qui n'est pas satisfait, avec sa cause

| Exigence | Statut | Cause et limite |
|---|---|---|
| REQ-04 Vérification des empreintes et analyse statique des 3 binair | NON SATISFAIT | échantillons des 3 binaires non fournis (preuve : `fourniture/` ne contient que les fiches, le LISEZ-MOI le dit) ; aucune empreinte recalculée, aucune analyse statique ; RFI-01 ouverte |
| REQ-07 Note de cadrage de 2 pages (fin J1) | PARTIEL | note de 2 pages produite et à jour, mais **après l'échéance « fin J1 »** (aucune journée réelle n'a séparé les phases) : critère de délai non satisfait ; équipe non communiquée |
| REQ-36 Dépôt Git local cti-helios-energy (exigence du sujet) | NON SATISFAIT | dépôt `cti-helios-energy` **non créé** : sa création n'a pas été approuvée le 2026-10-07 ; procédure complète prête (`preparer-depot-git.sh`) ; un essai à blanc ne vaut pas création |

## Visibilité dans les plateformes (vérifiée par API **et** dans les interfaces)

| Plateforme | Objets relus | Interface |
|---|---|---|
| MISP | événement 6 : 46 attributs, 5 objets, 8 galaxies, diffusion « organisation seulement », non publié | contrôlée (empreinte du certificat vérifiée) |
| OpenCTI | Analyses 1 (rapport de 103 objets), Événements (1 incident, 4 données observées, 4 détections), Observations (27 observables, 8 indicateurs, 4 infrastructures), 1 enquête en vue synthétique, 5 RFI | contrôlée les 2026-10-06 et 2026-10-07 : graphe de connaissance sur le rapport, enquête ouverte avec ses relations, RFI ouvertes sans réponse |
| Wazuh | 27 alertes `helios_challenge` (règles 130101 à 130115) | contrôlée : 27 résultats dans Discover |
| TheHive, Cortex | **non utilisés** | `05-Plateformes/Verification-TheHive.md`, `Verification-Cortex.md` |
