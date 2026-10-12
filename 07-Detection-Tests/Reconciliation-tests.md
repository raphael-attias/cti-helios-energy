# Réconciliation des tests de détection

Date : 2026-10-06 (revue de clôture). Tous les chiffres sont recomptés depuis les fichiers de résultats, pas recopiés. **Aucun de ces tests ne mesure un taux de faux positifs en production** : les négatifs sont des sosies écrits par l'équipe et un bruit Linux sans rapport avec les logsources Windows.

## 1. Ce que désigne chaque nombre

| Nombre | Unité de comptage | Jeu de données | Outil | Environnement | Commande / procédure | Fichier de preuve | Résultat | Limites |
|---|---|---|---|---|---|---|---|---|
| **162** tests Sigma | paires règle × événement (une ligne = une règle jugée sur un événement) | 410 événements en base SQLite (voir ligne suivante) | pySigma 1.5.1 + backend SQLite 2.0.0 | Mac de l'utilisateur, venv `cti-helios-env`, aucune connexion réseau | `python3 07-Detection-Tests/tester-sigma.py` | `Resultats-tests.csv`, `resultats/sortie-tester-sigma.txt`, `resultats/synthese-par-regle.csv` | 162 OK, 0 écart : 31 positifs attendus (18 sur événements du dossier, 13 sur synthétiques), 65 négatifs synthétiques, 51 autres événements du même logsource, 15 lignes « bruit agrégé » | **Moteur SQL, pas Wazuh** ; un test = un couple règle/événement, pas un événement |
| **410** événements Sigma | événements distincts de la base de test | 15 du dossier/fiches (E01-E15) + 13 positifs synthétiques (S01-S13) + 22 négatifs synthétiques (N01-N22) + 360 lignes de bruit syslog Linux du dossier (B001-B360) | `generer-sigma.py` (construction), `tester-sigma.py` | idem | idem | `Resultats-tests.csv`, `Plan-tests.md` §2 | 28 événements positifs distincts (15 + 13) = 31 couples règle/événement positifs (un événement peut déclencher deux règles) ; 0 faux négatif | Les 360 lignes de bruit n'ont aucun champ Windows : elles ne testent rien d'autre que « pas de plantage » ; **elles ne comptent pas comme des négatifs significatifs** |
| **45** cas Wazuh | événements distincts rejoués | 12 lignes du journal brut (**inchangées**) + 15 positifs synthétiques + 18 négatifs synthétiques | `wazuh-logtest` puis rejeu | voir 3 lignes suivantes | `jeux-tests/events-wazuh.tsv` | `jeux-tests/events-wazuh.tsv`, `Resultats-wazuh.csv` | 45/45 comportements attendus | Les 12 lignes du dossier sont attendues positives ; positifs synthétiques = **non-preuve** |
| **180** lignes Wazuh | 45 événements × **4 niveaux de test** | idem | (a) logtest en conteneur isolé sans réseau ; (b) logtest sur le manager de production (aucune alerte créée) ; (c) rejeu de bout en bout en conteneur isolé (`alerts.json`) ; (d) rejeu par l'API `POST /events` sur le manager de production | (a)(c) conteneur jetable sur la VM `wazuh` ; (b)(d) manager `single-node-wazuh.manager-1` | `wazuh/run_wz_test.sh`, `wazuh/run_wz_prod.sh` (`logtest`, `replay`) | `Resultats-wazuh.csv`, `resultats/wazuh-logtest-brut.json`, `wazuh-logtest-production-brut.json`, `wazuh-e2e-alertes-helios.json`, `wazuh-production-alertes-helios.json` | 180/180 OK (45 par niveau) | Les 4 niveaux ne sont **pas indépendants** : mêmes 45 entrées, mêmes règles ; ce sont 4 passages, pas 180 observations distinctes |
| **27** positifs / **18** négatifs | événements parmi les 45 | 27 = 12 du dossier + 15 synthétiques positifs ; 18 négatifs synthétiques | idem | idem | idem | `Resultats-wazuh.csv` | 27 événements doivent produire une alerte, 18 aucune ; observé conforme à chaque niveau | Négatifs = sosies écrits par l'équipe |
| **27** alertes indexées | documents `wazuh-alerts-*` du manager de production | produites par le niveau (d) | Wazuh 4.14.7, indexeur | production | rejeu API limité (3) puis complet (42) | `resultats/wazuh-production-alertes-helios.json` ; **relu par API** dans l'indexeur ; **relu dans le dashboard le 2026-10-06** (Discover, `wazuh-alerts-*`, `rule.groups:helios_challenge`, 27 hits, `rule.id` présent sur 27/27) | 27 | Alertes datées de l'heure de traitement (10:27 UTC), non de l'heure d'origine (dans `full_log`) |

Écart assumé : DET-002 (règle 130102) n'a **qu'une alerte** (1 positif sur 2 attendus par la logique Sigma) car l'autre événement est capté par la règle 130101 (ombrage, une seule alerte par événement ; `jeux-tests/ombrage.csv` : W01→130101 occulte 130102, W02→130103 occulte 130104, W10→130112 occulte 130106). Répartition par règle des 27 alertes : 130101 ×2, 130102 ×1, 130103 ×2, 130104 ×2, 130105 ×2, 130106 ×2, 130107 ×2, 130108 ×2, 130109 ×2, 130110 ×2, 130111 ×2, 130112 ×2, 130113 ×2, 130114 ×1, 130115 ×1. Les deux jeux (isolé et production) donnent la même répartition.

## 2. Distinction des natures de données

| Nature | Où | Statut |
|---|---|---|
| **Journaux fournis** | 12 lignes du journal brut ; détail de l'alerte 3 ; noms des fiches BIN-02/03 ; 360 lignes de bruit | seules données de preuve ; jamais modifiées |
| **Tests synthétiques** | 13 positifs et 22 négatifs (Sigma) ; 15 positifs et 18 négatifs (Wazuh) | écrits par l'équipe, **non-preuve**, étiquetés `synthétique` |
| **Alertes produites** | 27 documents Wazuh de production (et 27 de l'essai isolé, non indexés) | générées par le moteur à partir des lignes rejouées ; **ne prouvent pas que l'attaque a eu lieu**, elles prouvent que les règles fonctionnent |

## 3. Contrôles de cohérence interne (script)

`11-Validation/controle-coherence.py` vérifie 162 lignes Sigma et 180 lignes Wazuh, toutes OK. Les autres nombres (410, 45, 27, 18, 31 couples positifs, 28 événements positifs distincts, répartition par règle) ont été recomptés le 2026-10-06 par un script ponctuel de lecture des CSV, des TSV et des fichiers JSONL de `resultats/` ; ce script n'est pas conservé (limite : à reproduire avec `csv` et `json` si besoin).

## 4. Ce que ces tests ne montrent pas

Pas de taux de faux positifs en production ; pas de test sur les journaux réels de la victime (qui n'existent pas dans le dossier) ; pas de test de performance ; pas de test d'évasion ; Sigma et Wazuh sont testés par deux moteurs différents, **les règles Wazuh sont une adaptation manuelle, pas une conversion automatique des règles Sigma** (`Limites-detection.md`).
