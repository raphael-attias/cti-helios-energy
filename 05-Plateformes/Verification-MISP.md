# Vérification MISP après ingestion

Date : 2026-10-06. Instance : MISP 2.5.46 (production, CT 3012), `https://172.16.208.253`. Accès par l'API depuis l'hôte MISP via Ansible (Pharos), avec un **utilisateur dédié** `challenge-writer@helios.test` (rôle Publisher, organisation **CHALLENGE-FICTIF**, id 2). Aucune clé n'apparaît dans ce dossier.

## 1. Objets réellement présents (relecture par API)

| Élément | Valeur relue |
|---|---|
| Événement | **id 6**, uuid `33c1053e-e1e1-405f-ae75-b1c747a7f7b2`, « [CHALLENGE FICTIF] Helios Energy INC-2026-0302 », date 2026-03-02 |
| Propriétaire | organisation CHALLENGE-FICTIF (id 2) ; distribution 0 ; **non publié** ; analysis 1 (en cours) ; threat level 4 |
| Attributs top-level | 30 : sha256 3, domain 4, ip-dst 8, url 4, x509-fingerprint-sha1 3, text 4, filename 1, size-in-bytes 3 |
| Objets | 5 : `file` x3 (BIN-001 à 003), `domain-ip` x2 ; 16 attributs d'objets |
| Total attributs | **46**, dont **0 `to_ids`**, **0 doublon**, **0 corrélation** avec un autre événement |
| Relation | `downloaded-from` du fichier BIN-002 vers l'URL IOC-029 (taille corroborée par le journal) |
| Galaxies | 8 clusters MITRE ATT&CK Techniques, **techniques OBSERVÉES uniquement** : T1059.001, T1564.003, T1105, T1053.005, T1046, T1021.001, T1055, T1070.001 |
| Rapport d'événement | « Synthèse provisoire de l'analyse » |
| Étiquettes | `tlp:amber` et les 8 étiquettes de galaxie |

Aucune galaxie d'acteur ; aucune galaxie pour les techniques seulement probables ; T1055.012 et T1543.003 non étiquetées.

## 2. Comparaison au manifeste (`Evenement-MISP.json`) : écarts réels

| Écart | Cause | Traitement |
|---|---|---|
| Attribut `hostname` « comptabilite-07 » refusé | MISP exige un nom avec un point | stocké en `text` catégorie Other (la catégorie « Targeting data » est aussi refusée pour `text`) |
| `size-in-bytes` absent des 3 objets `file` | catégorie refusée à la création ; ajout dans un objet interdit au rôle Publisher (403) | 3 attributs libres `size-in-bytes` |
| Chemin `C:\Windows\Temp\~df3a9.tmp` devenu `%WINDIR%\Temp\~df3a9.tmp` | normalisation de MISP | transformation notée |
| Étiquettes `challenge:helios-fictif` et `challenge:source=dossier-pedagogique` non créées | le rôle Publisher ne peut pas créer d'étiquette | l'identification repose sur le titre, l'organisation et la distribution |
| Version des galaxies : T1070.001 | MISP porte l'ancien identifiant ; ATT&CK v19 = T1685.005 | noté dans l'événement STIX et les rapports |
| Export STIX avec galaxies en erreur | PyMISP incompatible avec les clusters par défaut | export réalisé avec `excludeGalaxy` |

## 3. Visibilité et isolation (ce qui est prouvé, ce qui ne l'est pas)

- **Interface MISP** : **contrôlée le 2026-10-06** en revue de clôture (compte administrateur de l'utilisateur déjà connecté ; certificat auto-signé accepté pour ce seul site après vérification de l'empreinte du serveur, sans désactiver les protections du navigateur) : événement 6, 46 attributs [5 objets], 8 galaxies, distribution « Your organisation only », non publié, tag `tlp:amber`, 1 rapport d'événement ; capture dans `11-Validation/preuves-consultation/`.
- **Isolation** : événement possédé par une organisation distincte avec distribution 0. Les comptes d'intégration d'OpenCTI (id 4, Read Only), TheHive (id 3, Publisher) et Cortex (id 2, Read Only) appartiennent à l'organisation stormlab (id 1) et ne sont pas administrateurs du site : d'après le modèle de droits MISP ils **ne devraient pas voir** cet événement. **Non prouvé empiriquement** (leurs clés n'ont pas été utilisées).
- **Connecteur MISP vers OpenCTI** : au moment du contrôle (journaux jusqu'à 11:47 UTC) il ne s'exécute pas (« Connector will not run until the queue messages size is reduced under queue threshold »), donc aucun import ; il n'a **aucun filtre** d'organisation, de distribution, d'étiquette ni de publication configuré. L'isolation repose donc sur la visibilité MISP seule. **Surveillance non réalisée** (la file n'a pas été vidée) : à faire seulement après vidage de la file : l'absence du rapport de l'événement dans OpenCTI.
- **TheHive** : import limité à l'étiquette `thehive:import` (documentation, non revérifié) ; l'événement ne la porte pas.

## 4. Retour arrière (non exécuté)

`cake user block challenge-writer@helios.test` ; suppression de l'événement 6, de l'utilisateur 5 et de l'organisation 2 par un administrateur. Aucune suppression n'est faite sans demande.

## 5. Corrélations

« Aucune corrélation avec d'autres événements » : constat de MISP (0 attribut corrélé). **Pas de corrélation déduite** de la simple présence des objets : la corrélation, si elle existe, est entre valeurs identiques ; ici aucune n'a été trouvée.

## 6. Cote Admiralty de l'équipe (2026-10-10)

Les 40 attributs d'IoC portent désormais, dans leur commentaire, la cote de l'équipe en plus de la cote du SOC : `cote ÉQUIPE admiralty-scale:source-reliability=C admiralty-scale:information-credibility=4 (C4)`. La fiabilité (A à F) et la crédibilité (1 à 6) restent séparées ; les cotes viennent de `02-Artefacts/Cotes-Admiralty-IoC.csv` (une ligne par IoC, justification incluse). Mise à jour par `misp_cotes_admiralty.py` après approbation explicite : 40 sur 40, 0 échec, relue par API (40 attributs sur 46 ; les 6 autres sont des noms de fichier et des tailles). Événement inchangé par ailleurs : non publié, distribution 0, 0 `to_ids`, 8 galaxies.

**Limite** : la cote n'est pas une étiquette. La taxonomie `admiralty-scale` existe dans MISP mais elle est désactivée, et le rôle Publisher ne peut ni l'activer ni créer d'étiquette ; elle n'est donc pas filtrable par tag. L'activer est un réglage global de l'instance partagée, non demandé ici. Procédure si vous la voulez : un administrateur active la taxonomie puis les 12 étiquettes utiles, et un second passage pose le tag sur chaque attribut.
