# Plan de tests et résultats

Date : 2026-10-06. Résultats détaillés : `Resultats-tests.csv` (162 lignes, Sigma sur SQLite), `Resultats-wazuh.csv` (180 lignes, Wazuh), dossier `resultats/` (sorties brutes). Scripts : `generer-sigma.py`, `tester-sigma.py`, `generer-jeux-wazuh.py`, `wazuh/run_wz_test.sh`, `wazuh/run_wz_prod.sh`.

## 1. Niveaux de test (à ne pas confondre)

| Niveau | Outil | Exécuté ? | Ce que cela prouve |
|---|---|---|---|
| 1. Validation syntaxique Sigma | pySigma 1.5.1 + validateurs | **oui**, 15 règles, 0 alerte (après correction d'un identifiant ATT&CK) | la syntaxe et les étiquettes sont valides |
| 2. Conversion | pySigma-backend-sqlite 2.0.0 (pipeline de renommage de champs) | **oui** | la logique se traduit en SQL ; **outil de test**, pas un déploiement |
| 3. Test sur événement (Sigma) | requêtes SQL sur 410 événements | **oui**, 0 écart | la logique donne le résultat attendu sur ces événements |
| 4. Décodage et règles Wazuh | `wazuh-logtest` (conteneur isolé, puis production) | **oui**, 45 événements, 45/45 | les décodeurs XML et règles adaptées donnent la règle attendue |
| 5. Rejeu de bout en bout isolé | conteneur manager sans réseau, fichier surveillé | **oui**, 27 alertes pour 27 positifs | la chaîne événement, décodage, règle, alerte fonctionne |
| 6. Rejeu en production | API Wazuh `POST /events`, manager de production | **oui**, limité (3) puis complet (42) | les alertes sont réellement générées et indexées |
| 7. Apparition dans le dashboard | interface Wazuh (Discover, `wazuh-alerts-*`) | **oui, le 2026-10-06 (revue de clôture)** : 27 hits sur `rule.groups:helios_challenge`, `rule.id` sur 27/27 ; captures dans `11-Validation/preuves-consultation/` | les 27 alertes sont visibles dans l'interface avec le bon filtre et la bonne période |

## 2. Jeux de données et leur statut

| Jeu | Contenu | Origine |
|---|---|---|
| Événements du dossier | 12 lignes ISO du journal brut (Sysmon, Squid, Zeek, Security), **inchangées** ; détail de l'alerte 3 (commande schtasks) ; noms des fiches BIN-02 et BIN-03 | dossier |
| Positifs synthétiques | 13 (Sigma) et 15 (Wazuh) | **SYNTHÉTIQUES**, écrits par l'équipe |
| Négatifs synthétiques | 22 (Sigma) et 18 (Wazuh), sosies bénins | **SYNTHÉTIQUES** |
| Bruit du dossier | 360 lignes syslog Linux du 2 mars | dossier ; ne s'applique qu'en contrôle croisé : les règles Windows n'y ont pas de champ à tester |

Les événements synthétiques ne sont jamais des preuves. Le rejeu Wazuh conserve les lignes du dossier telles quelles ; les alertes générées portent l'heure de traitement (2026-10-06), pas l'heure d'origine (conservée dans `full_log`).

## 3. Résultats Sigma par règle

| DET | Fondement | Logsource | Événements du logsource | Positifs obtenus (dossier + synthétiques) | Négatifs corrects | Faux positifs | Faux négatifs | Ajustement |
|---|---|---|---|---|---|---|---|---|
| DET-001 | DIRECTE | windows/process_creation | 16 | 2 | 14 | 0 | 0 | aucun après test |
| DET-002 | CHASSE | windows/process_creation | 16 | 2 | 14 | 0 | 0 | aucun après test |
| DET-003 | DIRECTE | proxy | 7 | 2 | 5 | 0 | 0 | aucun après test |
| DET-004 | IOC | proxy | 7 | 3 | 4 | 0 | 0 | aucun après test |
| DET-005 | DIRECTE | windows/process_creation | 16 | 2 | 14 | 0 | 0 | aucun après test |
| DET-006 | IOC | zeek/conn | 6 | 3 | 3 | 0 | 0 | aucun après test |
| DET-007 | DIRECTE | windows/process_access | 4 | 2 | 2 | 0 | 0 | aucun après test |
| DET-008 | DIRECTE | zeek/notice | 3 | 2 | 1 | 0 | 0 | aucun après test |
| DET-009 | DIRECTE | windows/security | 10 | 2 | 8 | 0 | 0 | aucun après test |
| DET-010 | DIRECTE | windows/create_remote_thread | 4 | 2 | 2 | 0 | 0 | aucun après test |
| DET-011 | DIRECTE | windows/security | 10 | 2 | 8 | 0 | 0 | aucun après test |
| DET-012 | DIRECTE | zeek/conn | 6 | 2 | 4 | 0 | 0 | aucun après test |
| DET-013 | DIRECTE | windows/security | 10 | 1 | 9 | 0 | 0 | identifiant ATT&CK : T1070.001 remplacé par T1685.005 (signalé par le validateur pySigma) |
| DET-014 | DIRECTE | windows/process_creation | 16 | 2 | 14 | 0 | 0 | idem DET-013 |
| DET-015 | IOC | windows/process_creation | 16 | 2 | 14 | 0 | 0 | aucun après test |

**Formulation exacte** : « aucun faux positif sur 410 événements testés (dont 360 lignes de bruit non applicables), 0 faux négatif sur 28 positifs ». Les négatifs sont des sosies écrits par l'équipe : **aucun taux de production n'est mesuré ni extrapolé**.

## 4. Résultats Wazuh par règle

| DET | Règle Wazuh | Positifs du dossier (logtest, rejeu isolé, rejeu production) | Faux positifs observés | Ajustement | Résultat final |
|---|---|---|---|---|---|
| DET-001 | 130101 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | niveau 4-7 en production | conforme |
| DET-002 | 130102 | 1 événement(s) attendus x 4 niveaux : 4/4 OK | 0 | niveau 4-7 en production | conforme |
| DET-003 | 130103 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | niveau 4-7 en production | conforme |
| DET-004 | 130104 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | niveau 4-7 en production | conforme |
| DET-005 | 130105 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | niveau 4-7 en production | conforme |
| DET-006 | 130106 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | niveau 4-7 en production | conforme |
| DET-007 | 130107 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | niveau 4-7 en production | conforme |
| DET-008 | 130108 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | niveau 4-7 en production | conforme |
| DET-009 | 130109 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | niveau 4-7 en production | conforme |
| DET-010 | 130110 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | niveau 4-7 en production | conforme |
| DET-011 | 130111 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | niveau 4-7 en production | conforme |
| DET-012 | 130112 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | ordre de la règle (ombrage) | conforme |
| DET-013 | 130113 | 2 événement(s) attendus x 4 niveaux : 8/8 OK | 0 | niveau 4-7 en production | conforme |
| DET-014 | 130114 | 1 événement(s) attendus x 4 niveaux : 4/4 OK | 0 | niveau 4-7 en production | conforme |
| DET-015 | 130115 | 1 événement(s) attendus x 4 niveaux : 4/4 OK | 0 | niveau 4-7 en production | conforme |

Faux positifs observés : **0 sur 18 négatifs**, aux 4 niveaux. Ombrage (une alerte par événement) : W01 (130101 et 130102), W02 (130103 et 130104), W10 (130112 et 130106).

## 5. Historique des corrections (détecter et corriger les erreurs)

| Étape | Constat | Correction |
|---|---|---|
| Premier `wazuh-analysisd -t` | « Field 'url' is static » | champs `url`, `status`, `user` renommés `http_url`, `http_status`, `win_user` |
| Deuxième | « Syntax error on tag dst_ip » | regex avec alternance passée en PCRE2 |
| Premier logtest (conteneur isolé) | **26 conformes sur 45** | décodeurs enfants : seul le premier était essayé, donc un `prematch` par décodeur enfant ; regex `.+` non prise en charge par OS_Regex, remplacée par `.*` |
| Deuxième logtest | 40 sur 45 (les 5 événements « Process Create » sans champs) | regex du décodeur « Process Create » passée en PCRE2 |
| Troisième logtest | **45 sur 45** | - |
| Conception des règles | 130112 masqué par 130106 sur la ligne 10 | ordre des règles inversé |
| Pré-production | seuil TheHive à 10 et e-mail à 12 | niveaux ramenés à 4-7 pour la production |
| Validateur pySigma | T1070.001 invalide | identifiant courant T1685.005 |

## 6. Accès aux résultats Wazuh (production)

Base de données `wazuh-alerts-*` (indexeur de l'infrastructure existante), **filtre `rule.groups: helios_challenge`**, ou `rule.id` de 130101 à 130115 ; index du jour `wazuh-alerts-4.x-2026.10.06` ; période 2026-10-06 de 10:26 à 10:28 UTC ; agent `wazuh.manager` ; `location: API-Webhook` ; 27 documents (vérifiés par l'indexeur). Exemples : alerte 130101, `full_log` « 2026-03-02T08:31:00Z comptabilite-07 Sysmon: Process Create: winword.exe -> powershell.exe … » ; 130113, « … Security: 1102 audit log cleared … ». Événements synthétiques identifiables par les noms d'hôtes `poste-test`, `srv-test`, `dc-test` et la date 2026-03-09. **Affichage dans le dashboard : non contrôlé.**
