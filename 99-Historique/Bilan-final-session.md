# Bilan final de session

> **Mis à jour par la revue de clôture du 2026-10-06 (seconde passe) : voir `Revue-cloture.md`. Les chiffres du corps du document sont ceux de la fin de session initiale (8 sur 35). Après révision : 33 sur 36 exigences officielles VALIDÉES selon les critères du §14 (contrôles techniques), 0 validée par le commanditaire ; REQ-15 à arbitrer, REQ-36 (dépôt Git) en attente d'approbation, REQ-04 bloquée. Formulation exacte pour la production : modifiée, sans effet de bord détecté dans le périmètre des contrôles réalisés.**

Date : 2026-10-06. **La mission n'est pas validée à 100 %.** Couvertures séparées (voir `00-Pilotage/Tableau-de-bord.md`) : exigences officielles **8 VALIDÉES sur 35 (22,9 %)**, 26 À CONTRÔLER, 1 BLOQUÉE ; demande supplémentaire OpenCTI 0 sur 1 ; optionnel 0 sur 6. Aucun livrable n'a été relu par le commanditaire.

## 1. Livrables produits et contrôlés

| Livrable | Fichier | Contrôle réellement exécuté |
|---|---|---|
| Inventaires (40 IoC, 12 alertes, 3 fiches), intégrité | `02-Artefacts/` | script, sha256 des originaux (identiques), CSV contre JSON |
| Analyse des 12 alertes (22 colonnes) | `04-Analyse/Matrice-analyse-alertes.csv`, `Analyse-alertes.md` | 29 extraits de preuve relus dans les originaux |
| Analyse des IoC, fiches, Diamond, attribution, cartographie, CID | `04-Analyse/` | cohérence chiffrée (somme des 40 entrées) ; pas de relecture tierce |
| Matrice ATT&CK, chronologie | `04-Analyse/` | 17 pages officielles lues ; **T1070.001 renuméroté T1685.005** ; tri chronologique |
| Bundle STIX, graphe | `06-STIX-Graphe/` | stix2-validator (valide, 0 erreur, 82 avertissements après révision de clôture), stix2, stix2-patterns, 466 références, régénération du graphe |
| 15 règles Sigma, tests, adaptations Wazuh | `07-Detection-Tests/` | pySigma 15/15, 410 événements Sigma sans écart, logtest 45/45 (isolé et production), rejeu isolé 27/27, production 27 alertes |
| Rapports PDF : cadrage (2 p.), stratégique (2 p.), tactique (11 p.), ANSSI (1 p.), TLP (1 p.), attribution, CID, questions, soutenance (15 diapositives) | `01-Cadrage/`, `08-Rapports/`, `10-Soutenance/`, `04-Analyse/` | pagination et rendu contrôlés par script et lecture d'images |
| Journaux J1 à J5, couverture des compétences, manifeste avec hashes, contrôle final | `09-Journal-mission/`, `11-Validation/` | `controle-coherence.py` |

## 2. Ingestions réellement réalisées

| Plateforme | Ce qui a été écrit | Isolation et garde-fous |
|---|---|---|
| **MISP** 2.5.46 (production) | organisation CHALLENGE-FICTIF, utilisateur Publisher dédié, événement 6 (46 attributs, 5 objets, 8 galaxies, rapport d'événement) | distribution 0, non publié, organisation propriétaire distincte, `to_ids=false` |
| **OpenCTI** 6.9.21 (production) | 47 objets étiquetés (dont 1 rapport, 3 notes, 1 incident, 4 données observées, 27 observables, 8 indicateurs, 3 systèmes), 26 relations, 4 détections, 3 organisations, 11 références, 6 labels, 2 PDF joints | TLP:RED, aucun domaine, label Jira non utilisé, indicateurs expirés, import automatique désactivé pour les PDF |
| **Wazuh** 4.14.7 (production) | 2 fichiers nouveaux (décodeurs, 15 règles niveaux 4 à 7), redémarrage de 41 s, 45 événements rejoués par l'API : 27 alertes | seuil TheHive 10, e-mail 12 ; 0 intégration, 0 réponse active |
| Cortex, CrowdSec | rien | analyseurs tiers ; aucune fonction pertinente |

Correction de ma part : ma première relation OpenCTI vers T1070.001 visait une entité minimale ; elle a été supprimée (objet du challenge) et remplacée par T1685.005. Mes scripts temporaires, la clé API dédiée et le conteneur de test ont été supprimés des hôtes.

## 3. Données réellement consultables

Contrôle initial **par API** ; **revue de clôture du 2026-10-06 : affichage contrôlé dans les trois interfaces avec réserves** (voir `Revue-cloture.md`).

- OpenCTI (`http://172.16.0.4:8180`) : rapport `/dashboard/analyses/reports/3ec91c0f-915b-4e1d-9cd9-c1c12c79f342` ; incident `/dashboard/events/incidents/a2f66075-be6c-42a9-9524-d428833fd4c1` ; filtre étiquette `challenge:helios-fictif`. Comptages relus : Analyses 4, Événements 9, Observations 35.
- MISP (`https://172.16.208.253`) : événement 6 (`/events/view/6`).
- Wazuh : `rule.groups: helios_challenge`, règles 130101 à 130115, index `wazuh-alerts-*`, 2026-10-06 de 10:26 à 10:28 UTC, 27 documents.
Détail et filtres : `05-Plateformes/Guide-consultation-OpenCTI.md`.

## 4. Tests exécutés et résultats

| Niveau | Résultat |
|---|---|
| Validation syntaxique Sigma (pySigma) | 15/15 après correction de l'identifiant ATT&CK |
| Test sur événement Sigma (SQLite) | 410 événements : **0 écart, 0 faux positif** (28 positifs, 22 négatifs synthétiques, 360 bruit) |
| `wazuh-logtest` isolé | 26/45, 40/45, puis **45/45** après corrections ; identique en production : **45/45** |
| Rejeu de bout en bout isolé | 27 alertes pour 27 positifs, 0 pour 18 négatifs |
| Rejeu en production par l'API | 27 alertes, 27 documents indexés, 0 négatif déclenché |
| Dashboard | contrôlé le 2026-10-06 : 27 alertes visibles (revue de clôture) |
Aucun taux de faux positifs de production n'est mesuré.

## 5. Attribution retenue et confiance

**Cluster non attribué.** Confiance élevée dans cette conclusion (aucune observation discriminante, aucune source indépendante) ; finalité lucrative : faible à moyenne (hypothèse) ; rapprochement d'outillage avec une famille connue : faible, non vérifiable ; acteur étatique : non soutenu. La piste du LISEZ-MOI est une indication, pas une preuve.

## 6. Limites de preuve

Aucun échantillon (« analyse des fiches fournies ») ; une seule ligne de balise ; journal Security de comptabilite-07 effacé ; 21 incohérences (dont compte utilisé avant sa création) ; dates = bornes d'observation ; cotes Admiralty plafonnées à C3 faute de sources indépendantes ; jeux de tests synthétiques ; tableau ATT&CK en v19 non reflété par toutes les plateformes ; statut OIV/SIIV non établi.

## 7. Exigences non satisfaites ou partielles

REQ-04 (bloquée) ; contrôle graphique des interfaces (SUP-01, volet Wazuh) ; équipe, rôles, temps (REQ-09, REQ-30) ; note de cadrage **remise après l'échéance J1** ; comptage des 25 objets STIX non démontré sous la définition conservatrice (20 analytiques, 24 avec identités ; 34 et 99 sous les définitions larges), arbitrage requis ; bundle dérivé de l'export MISP, pas un export pur ; enrichissement par sources ouvertes sur les IoC volontairement non réalisé ; Cortex, dépôt Git, CrowdSec, dark web non réalisés ; aucune relecture du commanditaire.

## 8. Actions précises restantes

1. Se connecter aux trois interfaces et contrôler les rubriques avec le guide (Q25).
2. Décider du retrait ou du maintien des objets de test (Q26) ; retrait Wazuh = suppression des deux fichiers `helios_decoders.xml` et `helios_rules.xml` puis `wazuh-control restart` ; MISP : bloquer l'utilisateur 5, supprimer l'événement 6 et l'organisation 2 ; OpenCTI : filtre par étiquette.
3. Surveiller l'absence d'import de l'événement MISP dans OpenCTI après la reprise de la file (Q28).
4. Communiquer équipe, rôles, temps (Q13) ; confirmer les exigences officielles (Q15) et le comptage STIX (Q14).
5. Obtenir les échantillons ou sorties de bac à sable, la source du RDP, le contenu de la sortie, la date de création de `svc-backup-temp`.
6. Revoir les règles de production avant tout usage réel (adaptation `eventchannel`, niveaux).
