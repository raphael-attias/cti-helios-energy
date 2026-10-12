# Vérification Cortex (document de contrôle interne)

Contrôle du 2026-10-07, **lecture seule**. Cortex 4.1.0 (`https://172.16.171.26`, conteneur `cortex` en bonne santé). **Constat : Cortex n'a pas été utilisé par la mission et n'a produit aucun résultat qu'elle cite.** Il ne figure ni dans les outils utilisés, ni dans les rapports, ni dans le support de soutenance, et aucun enrichissement Cortex n'est revendiqué.

## Accès et méthode

Cortex exige une clé ou une session. **Aucune clé ne m'a été fournie et je n'ai pas cherché à en obtenir** : la configuration de l'hôte n'a pas été fouillée, et le compte de démonstration que la documentation d'archive mentionne comme faible n'a pas été utilisé (il est à considérer comme compromis). La vérification s'appuie donc sur ce qui est lisible sans identifiant : le point `/api/status` et le **journal d'accès du conteneur** (`docker logs`), qui enregistre chaque appel d'API (méthode, chemin, source, code de retour) depuis le démarrage du conteneur le 2026-09-19 12:21 jusqu'au 2026-10-07 : 255 305 lignes.

## Constats

| Point | Résultat |
|---|---|
| Lancements d'analyseurs (`POST /api/analyzer/<id>/run`) | **478**, du 2026-09-19 au 2026-09-30, tous en succès (HTTP 200) ; sources : TheHive 433, OpenCTI (hiboux) 39, Pharos 6 |
| Lancements du 2026-10-01 au 2026-10-07 (période de la mission : 06 et 07/10) | **0** |
| Valeurs du dossier (14 valeurs : domaines, IP, hashes, noms de fichiers, `helios`) dans le journal | 0 occurrence d'une valeur d'IoC ; 2 occurrences de `helios` : **deux requêtes de recherche de jobs faites aujourd'hui depuis un poste non identifié (192.168.3.2), qui ont reçu une erreur HTTP 400**, donc une recherche qui échoue, pas une recherche sans résultat |
| Limite de cette méthode | le journal d'accès ne consigne pas les données des observables : l'absence de valeur dans le journal est un indice faible. **La preuve retenue est l'absence de tout lancement pendant la mission**, complétée par l'absence de toute valeur du dossier dans les 251 661 observables de TheHive (voir `Verification-TheHive.md`), seul appelant des 433 lancements |
| Lien TheHive vers Cortex | **en erreur** : 171 alertes de supervision (la dernière du 2026-10-07) indiquent que TheHive ne voit aucun analyseur Cortex (clé périmée ou régénérée) |
| Connecteur OpenCTI vers Cortex | présent en mode manuel (types IPv4, IPv6, domaine, nom d'hôte, URL, fichier), garde TLP à AMBER : **non déclenché** pour la mission, et ses objets sont en TLP:RED |
| Analyseurs du dossier de départ (`MISP_2_1`, `ThreatFox_1_0`, `URLhaus_2_0`, `VirusTotal_GetReport_3_1`) | interrogent des services tiers : leur emploi aurait transmis des valeurs d'IoC à des tiers, **non approuvé** |

## Distinctions

| Cas | Constat pour Helios |
|---|---|
| Job réellement lancé pour Helios | **aucun** |
| Job de production préexistant sur les mêmes valeurs | non démontrable ni exclu pour le 19-30/09 ; **sans lien avec la mission** (TheHive ne contient aucune de ces valeurs) |
| Job en échec, résultat inexploitable | aucun (478 succès, tous antérieurs à la mission) |
| Absence de job | **établie pour la période de la mission** |

## Décision

Aucun analyseur n'a été lancé pour remplir Cortex. Les rapports, la note de cadrage, le plan de tests, le support de soutenance et le bilan **ne citent pas Cortex comme outil utilisé ni comme contribution** ; l'enrichissement a été fait par lecture de sources officielles (ATT&CK, ANSSI, CNIL, FIRST, Légifrance) sans transmettre aucune valeur d'IoC à un tiers. Le volet Cortex du sujet est classé NON APPLICABLE dans la matrice, avec cette justification.
