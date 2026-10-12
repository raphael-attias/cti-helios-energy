# Version de MITRE ATT&CK : méthode retenue et vérification

Date de contrôle : 2026-10-06. Source de vérification : les **bundles STIX officiels de MITRE** (dépôt `mitre-attack/attack-stix-data`, fichiers `enterprise-attack-18.1.json`, `-19.0.json`, `-19.2.json`, téléchargés et lus par script, sha256 ci-dessous), pas un résumé de page web. Script : `04-Analyse/verifier-attack.py`. Résultat détaillé : `04-Analyse/Correspondance-ATTACK-v18-v19.csv`.

## Dates des versions (index officiel du dépôt de données)

| Version | Date de publication | Remarque |
|---|---|---|
| v18.0 | 28 octobre 2025 | |
| **v18.1** | 13 novembre 2025 | **version en vigueur du 13 novembre 2025 au 27 avril 2026, donc pendant l'incident (2 au 7 mars 2026)** |
| **v19.0** | **28 avril 2026** | date de sortie de la v19 (correction de « mai 2026 ») |
| v19.1 | 12 mai 2026 | c'est la date « dernière modification » affichée sur les pages de techniques : elle ne marque pas la sortie de la v19 |
| **v19.2** | 5 août 2026 | **version courante à la date de ce contrôle** |

sha256 des fichiers lus : v18.1 `f857d8f7…62fb`, v19.0 `df520ea0…626a`, v19.2 `dc1639ca…8f4` (valeurs complètes dans la sortie du script).

Une lecture de pages web plus ancienne dans cette session avait attribué la date du 28 avril 2026 à la v19.2 : c'était une erreur de résumé ; l'index officiel fait foi.

## Méthode retenue

**Cartographie selon la version actuelle (v19.2), avec correspondance historique v18.1 pour chaque technique.**

Raisons : (1) les règles Sigma validées par pySigma 1.5.1 emploient les étiquettes de la v19 (`attack.stealth`, `attack.defense-impairment`) et le validateur a rejeté l'ancien identifiant T1070.001 ; (2) les rapports sont rédigés après la sortie de la v19 et un lecteur ouvrira les pages actuelles ; (3) la correspondance ci-dessous permet de relire le dossier avec la version contemporaine de l'incident. Choisir la v18.1 comme version principale aurait obligé à modifier les règles Sigma, le bundle et tous les rapports, pour un gain nul.

## Vérification des huit techniques OBSERVÉES (bundles officiels)

| Technique (v19.2) | Nom officiel v19.2 | Statut v18.1 | Statut v19.0 / v19.2 | Identifiant en v18.1 | Tactiques v18.1 | Tactiques v19.2 |
|---|---|---|---|---|---|---|
| T1059.001 | PowerShell | active | active | T1059.001 | execution | execution |
| T1564.003 | Hidden Window | active | active | T1564.003 | defense-evasion | **stealth** |
| T1105 | Ingress Tool Transfer | active | active | T1105 | command-and-control | command-and-control |
| T1053.005 | Scheduled Task | active | active | T1053.005 | execution, persistence, privilege-escalation | idem |
| T1046 | Network Service Discovery | active | active | T1046 | discovery | discovery |
| T1021.001 | Remote Desktop Protocol | active | active | T1021.001 | lateral-movement | lateral-movement |
| T1055 | Process Injection | active | active | T1055 | defense-evasion, privilege-escalation | **stealth**, privilege-escalation |
| **T1685.005** | Clear Windows Event Logs | **absente** | active | **T1070.001** | defense-evasion (sous T1070.001) | **defense-impairment** |

Constats :
1. **Un seul identifiant diffère** : `T1070.001` (v18.1, active) est **révoquée** en v19.0 et remplacée par `T1685.005` (relation `revoked-by` du bundle officiel).
2. Les 7 autres techniques ont le **même identifiant et le même nom** en v18.1, v19.0 et v19.2.
3. **Les noms de tactiques changent en v19** : « Defense Evasion » est scindée en `stealth` et `defense-impairment`. Un lecteur qui cherche « Defense Evasion » dans la v19 ne le trouvera pas ; le dossier emploie les noms de la v19 (règles Sigma) ; les plateformes de production (MISP galaxie, base MITRE de Wazuh, entités minimales d'OpenCTI) portent l'ancien vocabulaire.

Les 10 autres lignes de `Matrice-ATTACK.csv` (techniques probables ou non retenues : T1003.001, T1008, T1048.003, T1055.001, T1055.002, T1055.012, T1071.001, T1078, T1136.002, T1543.003) sont toutes **actives et identiques en v18.1 et v19.2** (même script).

## Ce que cette vérification établit et ne dit pas

Établi : existence, statut, nom officiel et tactiques des 18 techniques de la matrice (et de T1070.001) dans trois versions officielles. Non établi : que chaque technique est bien démontrée par les artefacts (c'est le travail de la matrice d'analyse, avec ses statuts observée / probable / non démontrée), ni que les descriptions des pages n'aient pas évolué entre les versions (seuls identifiants, noms, statuts et tactiques sont comparés).
