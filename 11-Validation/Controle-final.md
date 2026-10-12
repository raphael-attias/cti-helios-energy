# Contrôle final

Date : 2026-10-06. Script : `controle-coherence.py` ; sortie réelle archivée : `controle-coherence-sortie.txt` (régénérée à chaque exécution). Statut de l'exigence REQ-34 : **SATISFAIT ET CONTRÔLÉ** (contrôle exécuté par l'agent ; un script de contrôle se contrôle lui-même et n'est pas relu par le commanditaire).

## 1. Ce que le script vérifie automatiquement

Originaux inchangés (7 sha256) ; 56 fichiers de l'arborescence cible présents ; pagination des PDF (cadrage 2, stratégique 2 à 3, tactique 8 à 12, ANSSI 1, TLP 1, soutenance) ; chiffres du bundle STIX et du rapport de validation ; inventaires (40, 12, 3) ; 15 règles Sigma et 11 / 3 / 1 par fondement ; 0 écart dans 162 tests Sigma et 180 lignes Wazuh ; 27 alertes de production archivées, aucune de niveau 10 ou plus ; matrice des alertes (12 lignes, 22 colonnes) ; T1070.001 et techniques écartées absentes des techniques retenues ; manifeste OpenCTI (27 observables, 8 indicateurs, 0 domaine) ; identifiants OpenCTI archivés et cités dans le guide ; absence de valeurs périmées dans le tableau de bord, la note de cadrage et le rapport stratégique ; absence de secret (motifs courants), de binaire et de document Office ; liens internes Markdown résolus.

## 2. Rapprochements demandés

| Rapprochement | Résultat | Preuve |
|---|---|---|
| Inventaire contre MISP | **40 entrées IoC = 27 attributs libres + 9 entrées dans 3 objets `file` + 4 entrées dans 2 objets `domain-ip`** ; l'événement contient 46 attributs parce que les objets `file` ajoutent le nom et la taille (3 tailles en attributs libres), l'hôte victime et le nom de tâche sont stockés en texte | `generer-evenement-misp.py`, `Verification-MISP.md` |
| MISP contre STIX | l'export MISP (78 objets) alimente 71 objets du bundle ; 7 `x-misp-attribute` retirés avec conversion documentée ; écart : les galaxies n'apparaissent que comme étiquettes (export impossible avec galaxies) | `Rapport-validation-STIX.md` T1 à T7 |
| STIX contre graphe | le graphe est généré **depuis** `Bundle-STIX.json` : 41 nœuds et 43 arêtes affichés sur 152 objets, filtre documenté | `Script-generation-graphe.py` |
| STIX contre OpenCTI | pas de lien automatique : l'OpenCTI reçoit ses objets par écriture directe ; différences voulues : pas d'observable de domaine, T1685.005 avec l'entité MITRE, indicateurs expirés | `Verification-OpenCTI.md` |
| Inventaire contre OpenCTI | 40 entrées : 31 couvertes par 27 observables (9 entrées fusionnées en 3 fichiers, IOC-039 en 2 objets) + 9 exclues (6 domaines, IOC-036, 038, 040 en entité système) ; observable extrait supplémentaire : 1 URL | `Manifeste-OpenCTI.json` (contrôle par script) |
| Chronologie contre rapports | dates reprises des journaux ; bornes d'observation jamais présentées comme début et fin ; mémo daté avant les faits signalé partout | `Chronologie.csv`, rapports |
| Attribution contre sources | aucune source indépendante ; piste du LISEZ-MOI classée comme indication ; aucune relation d'acteur dans MISP, OpenCTI, STIX | `Hypotheses-et-attribution.md`, contrôle « aucun acteur dans le bundle » |
| Règles contre artefacts | chaque règle DIRECTE cite alerte et ligne de journal dans `Registre-regles.csv` ; 3 règles IOC et 1 règle de chasse sont étiquetées et ne prouvent aucune technique | `Registre-regles.csv` |
| Risques contre actifs | la matrice CID ne contient que des actifs avec preuve d'atteinte (comptabilite-07, srv-fichiers-02, dc-01, volume sorti, compte) ; annuaire compromis et système industriel non affirmés | `Matrice-risques-CID.csv` |
| Rapport direction contre rapport SOC | mêmes faits chiffrés (2 469 135 790 octets, 21 incohérences, 15 règles, cluster non attribué) ; la direction reçoit les décisions et priorités, le SOC les preuves | lecture croisée et contrôle de valeurs périmées |

## 3. Limites du contrôle

Pas de relecture humaine ; tests écrits par l'équipe ; pas de contrôle graphique des interfaces ; le script ne peut pas juger la justesse analytique, seulement la cohérence et la présence ; le manifeste ne contient pas son propre hash (autoréférence).

## 4. Tirets longs

Les noms d'objets exacts demandés par le commanditaire (« Helios Energy — Investigation CTI », « Helios Energy — Intrusion ») contiennent un tiret long ; les autres documents n'en utilisent pas (le script en liste les occurrences).
