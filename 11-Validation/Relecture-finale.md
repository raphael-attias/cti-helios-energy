# Relecture finale (2026-10-07)

**Nature de cette relecture** : critique, faite par l'agent qui a produit le dossier. Ce n'est **ni une relecture indépendante par un tiers, ni une validation du commanditaire**, ni un avis de formateur. Elle compare chaque conclusion importante à sa preuve (alerte, ligne de journal, inventaire, sortie d'outil) et chaque chiffre aux fichiers sources, au-delà de la recherche de placeholders.

## 1. Portée réelle

| Niveau de lecture | Documents |
|---|---|
| Lus en entier et comparés aux preuves | rapport stratégique, note d'attribution, hypothèses et attribution, note de partage TLP, note ANSSI, note de cadrage, préparation aux questions de soutenance, rapport de validation STIX, justification des 25 objets liés, diagnostic OpenCTI, procédures Git et restes en production |
| Lus par sections ou par sondage, avec les preuves ouvertes | rapport tactique (résumé, chronologie, §10 à §14, alertes 5, 6, 9 et 10 contre `05_journaux_bruts.log` lignes 8, 5, 9 et 10 : conformes), matrice CID (chaque actif et l'échelle), Diamond Model, analyse des IoC (synthèse chiffrée), analyse des fiches binaires (tableau des affirmations), journaux J1 à J5 (en-têtes et sections de limites), plan de tests (historique des corrections), guide de consultation |
| **Contrôlés par script seulement, non relus ligne à ligne** | analyse détaillée des 12 alertes (`Analyse-alertes.md`, `Matrice-analyse-alertes.csv`) : 29 extraits relus automatiquement dans les originaux ; chronologie (34 lignes : références résolues) ; cartographie SI ; règles Sigma et registre des règles ; scripts de reproduction |

## 2. Défauts trouvés et corrigés

| # | Document | Défaut | Correction | Preuve du contrôle | Résultat |
|---|---|---|---|---|---|
| 1 | Rapport stratégique §5 | confiance « élevée » fondée sur « plusieurs lignes de journal », alors que chaque alerte n'a **qu'une** ligne correspondante (`Integrite-et-provenance.md`, contrôle 4) et que les cotes sont plafonnées à C3 | réécrit : moyenne à élevée sur les actions, moyenne sur leur sens, faible sur les capacités et l'enchaînement | relu contre `Integrite-et-provenance.md` et `Analyse-IoC.md` §2 ; PDF régénéré (2 pages) | corrigé |
| 2 | Rapport stratégique §2 | une session à distance « par ce compte » listée comme établie alors qu'elle précède de 36 h la création du compte (I-03) | reformulé, avec l'inconnu correspondant ajouté | `Chronologie.csv`, I-03 | corrigé |
| 3 | Rapport stratégique §3 | « extorsion possible (hypothèse) » : reprise implicite de la piste du LISEZ-MOI | reformulé en possibilité générique sans demande ni chiffrement observés | `Indication-dossier-pedagogique.md` | corrigé |
| 4 | Rapport stratégique | aucun marquage TLP alors que la note de partage le classe AMBER+STRICT | marquage ajouté en en-tête | `Note-partage-communautaire.md` §2 | corrigé |
| 5 | Rapport stratégique §1 | « 2,5 Go » sans les octets ni l'écart avec « 2,3 Go » de l'alerte (I-10) | octets et unité ajoutés | `Integrite-et-provenance.md` I-10 | corrigé |
| 6 | Note d'attribution, hypothèses, rapport tactique §10, support | « finalité lucrative faible à moyenne » : la chaîne observée n'est pas discriminante, ce qui contredit la note elle-même ; acteur étatique « non soutenu » sans « non exclu » | finalité lucrative : faible, non discriminante ; acteur étatique : non soutenu, non exclu | `Hypotheses-et-attribution.md` §1 et §4 | corrigé |
| 7 | Rapport de validation STIX §4 | rapport, regroupement et notes comptés « analytiques » (27), incompatible avec les comptages 20 et 24 ; chiffre « 130 sur 133 » incluant les relations | tableau réécrit en catégories séparées ; chiffres expliqués | `Justification-25-objets-lies.md` | corrigé |
| 8 | Rapport de validation STIX, plusieurs autres documents, scripts de contrôle | chiffres périmés après l'ajout T13 (133 objets, 82 avertissements, 466 références, 32 relations, graphe de 32 nœuds) | mis à jour : 152 objets, 101 avertissements, 547 références, 44 relations, 41 nœuds ; contrôles de cohérence mis à jour | `controle-coherence.py` : 42 contrôles, 0 écart | corrigé |
| 9 | Bundle STIX | identité « Équipe CTI » avec la mention « Composition : à confirmer » | « Composition non communiquée » | bundle régénéré, validé (0 erreur) | corrigé localement ; le même texte dans OpenCTI n'est pas modifié (limite) |
| 10 | Préparation aux questions Q5, Q7, Q12, Q14, Q17, Q18 | renvoi à une question non suivie (Q9) ; « demande explicite du commanditaire » (autorisation générale, puis approbation par opération) ; connecteur MISP « en pause » ; graphe de l'incident « non rendu » (il n'existe pas) ; comptage des 25 objets périmé ; « trois passes » de logtest | corrigés | `Controle-live-2026-10-07.md`, `Plan-tests.md` §5 | corrigé |
| 11 | Diapositive 11, rapport tactique §11 | « 26/45 puis 45/45 après 3 corrections » et « quatre itérations », alors que `Plan-tests.md` donne 26, 40, 45 (trois passes, deux corrections) | harmonisé sur trois passes et deux corrections | `Plan-tests.md` §5 | corrigé |
| 12 | Matrice CID | le même événement (alerte 10) fonde l'impact C observé de dc-01 **et** de la ligne « Données sorties », sans avertissement | avertissement « ne pas additionner » ajouté ; PDF régénéré | `Matrice-risques-CID-rapport.md` | corrigé |
| 13 | Journaux J1 et J2 | Cortex listé parmi les outils | retiré ; « ni Cortex ni TheHive » écrit | `Verification-Cortex.md` | corrigé |
| 14 | Note de cadrage | Cortex compté parmi les éléments optionnels sans dire qu'il n'est pas utilisé | reformulé (non applicables, non utilisés) | PDF régénéré, 2 pages | corrigé |
| 15 | Support de soutenance, diapositive 1 | « à confirmer » | « non communiqués » | texte du PDF relu | corrigé |
| 16 | Guide de consultation, diagnostic, vérification OpenCTI, méthodes, tableau de bord | comptages OpenCTI périmés (85 objets au rapport, 12 relations de l'incident, aucune infrastructure) | 103 objets, 27 relations, 4 infrastructures | API relue le 2026-10-07 | corrigé |
| 17 | Journal J2, matrice | connecteur MISP vers OpenCTI « en pause » | « en marche mais sans interrogation de MISP » | `Controle-live-2026-10-07.md` | corrigé |
| 18 | Pièces jointes du rapport OpenCTI | versions antérieures aux PDF finaux (tactique 10 pages, stratégique ancien) | remplacées après approbation (deux passages pour le tactique, voir 21) ; anciennes versions archivées | taille et nom relus par API ; sha256 dans `Remplacement-PDF-joints.json` | corrigé |
| 19 | RFI-05 dans OpenCTI | texte périmé (20, 24, 34, 99 ; fichier d'ajouts supprimé) | mis à jour après approbation | `octi_rfi05_maj.py verify` : statut NEW, priorité P2, liens et marquage inchangés | corrigé |
| 20 | `06-STIX-Graphe/Liaison-STIX.md` | document périmé présenté dans le dossier final | déplacé dans `99-Historique/` ; références redirigées vers la justification des 25 objets | recherche des références | corrigé |
| 21 | Rapport tactique (PDF) et graphe CTI | le graphe, réduit à une vignette sur une page portrait, était illisible ; l'en-tête de colonne recouvrait un nœud ; les données observées portaient le libellé « ... » | en-têtes déplacés, libellés « observation de <valeur> », annexe pivotée de 90° avec renvoi au PDF vectoriel `Graphe-CTI.pdf` ; le rapport tactique est remplacé une seconde fois dans OpenCTI (même approbation), version intermédiaire archivée | rendu des pages relu, 11 pages ; taille relue par API | corrigé |

## 3. Vérifications sans défaut trouvé

| Point | Contrôle | Résultat |
|---|---|---|
| Statut OIV | fourni par l'énoncé dans la note ANSSI, le cadrage et le stratégique ; SIIV et secteur inconnus | cohérent |
| Sources réglementaires et TLP | note ANSSI et note de partage relues (TLP 2.0, CLEAR à la place de WHITE, équivalences AMBER et AMBER+STRICT) | cohérent |
| Attribution indépendante du LISEZ-MOI | la piste est classée « indication, pas preuve » dans l'attribution, les hypothèses, le Diamond, le tactique et la soutenance ; aucun acteur dans le bundle (contrôle script) | cohérent |
| Fiches binaires | aucune affirmation d'analyse de binaire : « analyse des fiches fournies », aucun hash recalculé (`Analyse-binaires.md`, tactique §6, cadrage, soutenance Q6) | cohérent |
| Cortex et TheHive | aucune contribution revendiquée dans les rapports, le support ou la clôture ; absence d'usage expliquée dans `Verification-Cortex.md` et `Verification-TheHive.md` | cohérent |
| Méthodes d'import | `Methodes-integration-et-import.md` comparé au journal d'ingestion ligne à ligne ; l'insertion SQL est présentée comme exception non recommandée | cohérent |
| Recommandations reliées aux risques | tableau du stratégique §6 : chaque priorité cite son observation | cohérent |
| Chiffres et dates | 40 IoC, 12 alertes, 21 incohérences, 15 règles, 162 tests, 410 événements, 45 cas, 180 lignes, 27 alertes, 27 objets liés : recoupés entre documents ; dates d'observation 2 au 7 mars, journées réelles toutes au 2026-10-06 | cohérent après les corrections ci-dessus |
| Secrets | motifs courants, jetons, clés : 0 trouvé ; aucun binaire ni document Office | 0 |
| PDF | pagination : cadrage 2, stratégique 2, tactique 11 (10 pages de texte et le graphe), attribution 2, ANSSI 1, partage 1, questions 2, CID 2, support 15 ; aucun « à confirmer », « Cortex » comme outil ni « FIN7 » comme conclusion | conforme (1 mention de FIN7 dans la note d'attribution et dans les questions : c'est la piste rejetée) |
| Originaux | sha256 des 7 fichiers de `fourniture/` identiques à l'inventaire | intègres |
| Pièces jointes OpenCTI | tailles et noms identiques aux PDF locaux finaux | cohérent |

## 4. Limites de cette relecture

Faite par l'auteur, donc exposée à ses angles morts ; les parties du §1 « contrôlées par script seulement » n'ont pas eu de relecture critique ligne à ligne ; le jugement analytique (cotes Admiralty, criticités CID, méthode d'analyse de risques) n'est relu par aucun tiers. Rien ici ne vaut validation du commanditaire.
