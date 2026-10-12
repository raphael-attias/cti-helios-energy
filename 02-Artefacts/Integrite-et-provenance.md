# Intégrité et provenance des artefacts

Contrôle du 2026-10-06. Les originaux sont dans `fourniture/` (jamais modifiés ; sha256 relus après exécution du script, identiques à la première lecture). Les fichiers datent du 2026-09-23 (horodatage système), ce qui donne la date de dépôt connue ; la provenance amont (qui a produit les fichiers, comment) est **INCONNUE**.

## Empreintes des fichiers sources

| ID | Fichier | Taille (octets) | Lignes | sha256 |
|---|---|---|---|---|
| ART-001 | 00_LISEZ-MOI.md | 1488 | 26 | b07b83f2…cbc346fd |
| ART-002 | 01_fiches_analyse_binaires.md | 3997 | 95 | ec40b164…1e734 (voir `Inventaire-artefacts.csv` pour les valeurs complètes) |
| ART-003 | 02_indicateurs_40.csv | 4546 | 41 | 48b23612… |
| ART-004 | 02_indicateurs_40.json | 8810 | 281 | 41266a1f… |
| ART-005 | 03_alertes_siem_12.csv | 2041 | 13 | fd712d00… |
| ART-006 | 04_memo_technique_SOC.md | 2046 | 42 | 9cc2e0ed… |
| ART-007 | 05_journaux_bruts.log | 32452 | 372 | bc55524a… |

Les valeurs complètes et le script de génération sont dans `Inventaire-artefacts.csv` et `generer-inventaires.py` (sortie archivée : `sortie-generer-inventaires.txt`).

## Comptages (conservés séparément)

| Mesure | Valeur |
|---|---|
| IoC, lignes CSV d'origine / JSON | 40 / 40 |
| IoC uniques / doublons / invalides | 40 / 0 / 0 |
| Répartition par type | ipv4 10, sha256 6, domain 6, host 5, url 4, sha1 3, md5 3, sha1-cert 3 |
| Alertes SIEM | 12 |
| Fiches de binaires / échantillons fournis | 3 / **0** |
| Lignes du journal brut | 372 (12 au format ISO 8601 UTC = les 12 alertes ; 360 lignes de bruit syslog) |
| Indicateurs extraits pendant l'analyse | 15 (`Indicateurs-extraits.csv`) |

Les 40 valeurs d'IoC sont toutes dans des plages réservées à la documentation (IPv4 RFC 5737 : 198.51.100.0/24 et 203.0.113.0/24 ; domaines `.test`). Le LISEZ-MOI cite aussi RFC 3849 (IPv6) mais **aucun IoC IPv6 n'existe** dans le lot.

## Contrôles automatiques exécutés (réels)

1. CSV et JSON des IoC identiques ligne à ligne : 40/40.
2. Formats des empreintes valides (longueur et caractères) : 0 invalide.
3. Les 9 empreintes des trois fiches de binaires existent dans le CSV (BIN-001 → IOC-001/002/003, BIN-002 → IOC-004/005/006, BIN-003 → IOC-007/008/009) : 0 écart.
4. Chacune des 12 alertes a **une** ligne ISO correspondante (même horodatage et même hôte) dans le journal brut.
5. La taille de BIN-002 déclarée (421376 octets) correspond à la taille de la réponse HTTP dans la ligne Squid de 08:42 (`200 421376`) : **corroboration** entre deux artefacts du même fournisseur.

Limite : ces contrôles prouvent la cohérence interne du lot, pas sa véracité.

## Incohérences et réserves relevées dans les sources (à traiter, pas à effacer)

| # | Constat | Artefacts | Traitement retenu |
|---|---|---|---|
| I-01 | Le LISEZ-MOI annonce des alertes « dans l'ordre chronologique », mais l'alerte 5 (2026-03-05T14:07Z) précède les alertes 6, 7 et 8 (3 et 4 mars). | ART-001, ART-005 | Tri par horodatage dans la chronologie ; l'ordre d'origine est conservé dans l'inventaire. |
| I-02 | Le mémo est daté du 2026-03-02T10:30Z mais décrit des événements du 5 mars (LSASS, exfiltration, « quatrième jour »). Un mémo « initial » ne peut pas connaître ces faits à cette date. | ART-006 | Date du mémo traitée comme **non fiable** (probable mise à jour sans changement d'en-tête). Hypothèse, non démontrée. |
| I-03 | Le compte `svc-backup-temp` ouvre une session RDP sur srv-fichiers-02 le 2026-03-04 à 01:47 (événement 4624), mais sa création (4720) date du 2026-03-05 à 14:12 sur dc-01. La session précède la création de 36 h. | ART-005 (alertes 7, 9), ART-007 | Contradiction non résolue. Hypothèses à ouvrir : compte antérieur du même nom, horloge ou fuseau erroné, journal reconstitué. |
| I-04 | Alerte 7 : « source interne inhabituelle » pour le RDP ; IoC 26 : l'IP 203.0.113.44 est une « connexion RDP entrante » donc externe. | ART-005, ART-003 | Source du RDP **INCONNUE** tant que non tranchée. |
| I-05 | Alerte 6 et IoC 25 : 198.51.100.55 « scanne le sous-réseau 10.20.0.0/16 depuis le poste compromis ». Une adresse publique (documentation) ne peut pas être la source d'un balayage interne direct. | ART-005, ART-003, ART-007 | Interprétation ouverte (champ mal renseigné, NAT, ou IoC mal attribué). |
| I-06 | Alerte 8 : technique T1055.012 (process hollowing), mais le journal montre `CreateRemoteThread into explorer.exe RWX region`, ce qui décrit plutôt une injection par thread distant. La fiche BIN-02 parle aussi de « creux de processus » dans un `explorer.exe` existant. | ART-005, ART-007, ART-002 | Mapping ATT&CK à **vérifier sur la source officielle** avant tout usage (REQ-17). |
| I-07 | Alerte 8 : l'injection est sur srv-fichiers-02, alors que BIN-02 est récupéré sur comptabilite-07. La présence de BIN-02 sur srv-fichiers-02 n'est qu'**inférée** (IoC 11). | ART-005, ART-002, ART-003 | Mouvement latéral comptabilite-07 vers srv-fichiers-02 : **mécanisme inconnu**. |
| I-08 | Alerte 5 : le journal indique un accès à LSASS « by rundll32_helper.dll ». Une DLL n'est pas un processus ; l'hôte du chargement (probablement rundll32.exe) n'est pas nommé. | ART-007 | À signaler comme imprécision de source, sans compléter. |
| I-09 | Alerte 9 : « svc-backup-temp créé à 14:10 » mais horodatage d'alerte et événement 4720 à 14:12 ; suppression à 14:55 (détail) ou « 45 min plus tard » (log). Écart de 2 min et ambiguïté de 2 min sur la suppression. | ART-005, ART-007, IoC 37 | Écart mineur, noté. |
| I-10 | Alerte 10 : « 2,3 Go » ; journal : 2 469 135 790 octets, soit 2,30 Gio ou 2,47 Go. L'unité n'est pas précisée. | ART-005, ART-007 | Utiliser les octets bruts dans les rapports. |
| I-11 | Alerte 11 (2026-03-06T03:10Z) parle d'une bascule vers `static-assets-cache.test` « après perte du C2 principal », mais l'IoC 16 et l'IoC 22 (infrastructure de repli) sont vus dès le 2026-03-03 à 02:00 et 03:22. | ART-005, ART-003 | Le repli est connu avant d'être utilisé : à expliquer ou à laisser en inconnu. |
| I-12 | Deux « serveurs de commande » distincts : balise vue vers 198.51.100.24 (alerte 4, journal Zeek) et « serveur de commande principal » 203.0.113.14 (IoC 21). | ART-003, ART-007 | Relation entre les deux : non établie. |
| I-13 | Les fiches renvoient à des identifiants (D-01, D-02, D-04, IP-07, IP-08, IP-09, CERT-01, HASH-STAGE) qui ne correspondent pas aux numéros `#` du CSV. L'ordre d'apparition fait coïncider les domaines (D-01 = IoC 13, D-02 = IoC 14, D-04 = IoC 16) mais **pas** les IP (IP-07/08/09 ne tombent pas sur des serveurs de commande ou d'exfiltration). | ART-002, ART-003 | Correspondance IP **non résolue** ; ne pas la supposer. Non clarifiée (RFI-02 ouverte). |
| I-14 | IoC 18 : le domaine `update-win-msft.test` est décrit comme « nom de tâche planifiée associé » alors que la tâche s'appelle `MicrosoftEdgeUpdateTaskMachine` (IoC 36). Sens du contexte flou. | ART-003 | Contexte à ne pas surinterpréter. |
| I-15 | IoC 28 (D4) et IoC 35 (C4) renvoient à un rapport public et à une campagne de janvier 2026 non fournis. | ART-003 | Non vérifiables : traités comme HYPOTHÈSE. Aucune recherche externe n'a été lancée (décision Q12). |
| I-16 | Le journal brut n'a qu'une seule journée de bruit (2 mars, 02:12 à 14:11), sans année ni fuseau, au format syslog Linux (`systemd`, `sshd`, `CRON`, `UFW`) pour des hôtes qui émettent par ailleurs des événements Windows (Sysmon, Security). | ART-007 | Le bruit ne couvre pas la période 3 à 7 mars. À prendre en compte pour tout jeu de test négatif (volume et réalisme limités). Il n'y a **aucun** IoC dans le bruit (recherche par motifs : `.test`, plages 198.51.100/203.0.113, `svc-backup`, `lsass`, `powershell`, `wevtutil`, `MicrosoftEdge`, `rundll32`, `svchost_update`, `helios` ; recherche non exhaustive des 40 valeurs). |
| I-17 | Les fiches écrivent « comptabilité-07 » (avec accent) dans la fiche BIN-02, « comptabilite-07 » partout ailleurs. | ART-002 | Normalisation sans accent. |
| I-18 | Alerte 1 : le parent du PowerShell est `winword.exe` (Word) alors que BIN-01 est un classeur `.xlsm` (Excel) et que le mémo parle d'un classeur Excel. | ART-005, ART-007, ART-002, ART-006 | Parent mal étiqueté ou artefact initial différent : non tranché (Q7, limite définitive). |
| I-19 | Alerte 12 titrée « tentative » alors que l'événement 1102 atteste un effacement effectif du journal Security. | ART-005, ART-007 | Perte probable d'événements Security sur comptabilite-07 ; absence de preuve non probante. |
| I-20 | Alerte 3 : la commande `schtasks /create` n'apparaît que dans le détail de l'alerte, pas dans le journal brut ; le libellé `Sysmon: Scheduled Task Created` n'est pas, à ma connaissance, un événement Sysmon standard. | ART-005, ART-007 | Origine réelle du journal inconnue (limite). |
| I-21 | Des éléments de détail d'alerte sont absents des lignes brutes : « non signé » (alerte 5), « source interne inhabituelle » (7), « toutes les ~300 s » (4), « après perte du C2 principal » (11). | ART-005, ART-007 | Le détail du SIEM n'est pas une preuve brute. |

## Remarque sur le LISEZ-MOI

Le LISEZ-MOI (voir aussi `04-Analyse/Indication-dossier-pedagogique.md`) contient une section « Piste d'attribution » qui annonce la réponse attendue. **Elle n'est pas une preuve.** Elle sera consignée comme avis de cadrage dans `Journal-decisions.md` et l'attribution sera construite uniquement à partir des artefacts, avec examen d'hypothèses alternatives, pour éviter un biais de confirmation.

## Dates

- Date d'acquisition (analyse) : 2026-10-06.
- Date des événements : 2026-03-02 à 2026-03-07, fuseau UTC (suffixe Z) pour tout ce qui est en ISO 8601 ; le bruit syslog n'a **pas** de fuseau.
