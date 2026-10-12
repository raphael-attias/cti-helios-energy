# Consultation dark web : cadre, méthode et journal

Date : 2026-10-12. Périmètre : incident INC-2026-0302 (Helios Energy, victime fictive). Exigence : le dark web est **strictement consultatif** ; chaque consultation est horodatée et tracée ; aucune interaction avec un vendeur ; aucun achat d'échantillon.

## 1. Règles appliquées

| Règle | Application |
|---|---|
| Consultation seule | lecture de pages, aucune écriture, aucun formulaire, aucun message |
| Aucune interaction | aucun compte créé, aucun contact avec un vendeur, un courtier d'accès ou un groupe |
| Aucun achat | aucun échantillon, aucune donnée, aucun accès acheté ou demandé |
| Aucune valeur du dossier envoyée à un tiers | aucun IoC, aucun nom d'hôte, aucun nom de victime n'est saisi dans un moteur ou une page ; les recherches portent sur des thèmes génériques (groupe cité par la piste du dossier, sources de renseignement) |
| Traçabilité | chaque consultation figure dans [Journal-collecte.csv](Journal-collecte.csv) (date, heure, cible, résultat réel, données envoyées : non) et dans le tableau du §3 |
| Sources cotées | chaque source est enregistrée dans [Registre-sources.csv](Registre-sources.csv) avec une cote de fiabilité Admiralty |

## 2. Méthode : consultation indirecte par des sources en clair

Aucune connexion directe à un service `.onion` n'a été faite (pas de navigateur Tor). Le dark web est consulté **par ricochet**, à travers des sources publiques en clair qui le surveillent, le cataloguent ou en tirent des constats :

1. un **catalogue de sources** du web profond et du dark web (forums, places de marché, sites de fuite de groupes de rançongiciel, canaux Telegram), pour savoir quelles sources un analyste consulterait et par quelle voie ;
2. un **suivi de sites de fuite** de groupes de rançongiciel, pour observer l'activité publiée par les groupes sans visiter leurs sites ;
3. la **fiche officielle du groupe** désigné par la piste du dossier (FIN7), pour confronter ses techniques documentées à celles observées.

Ce choix répond à la contrainte du sujet (consultation seulement, risque minimal) et au fait que les IoC du dossier sont des plages de documentation et des domaines `.test` : une recherche de leurs valeurs sur une place de marché clandestine ne peut rien donner et n'est pas faite.

## 3. Journal des consultations (heures UTC, relevées à la consultation)

| # | Date et heure | Source | Cible | Objectif | Ce qui a été lu | Interaction | Donnée du dossier envoyée |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-12 ≈05:38Z | SRC-019 | `github.com/fastfire/deepdarkCTI` | connaître les catégories de sources du dark web utiles en CTI | dépôt public qui catalogue des sources : canaux Telegram et Discord, sites de fuite de groupes de rançongiciel, forums de cybercriminalité et de fuite de données, places de marché, services de logiciels malveillants, bases d'exploits, phishing, moteurs de recherche. Aucune date de mise à jour visible. Les courtiers d'accès initial n'apparaissent pas comme catégorie distincte | aucune | non |
| 2 | 2026-10-12 ≈05:39Z | SRC-020 | `www.ransomware.live` | mesurer l'activité publiée sur les sites de fuite | suivi public des victimes publiées par des groupes de rançongiciel : 32 605 victimes suivies, 407 groupes actifs, 8 017 victimes dans l'année, 362 dans le mois, dernière découverte affichée le 2026-10-12. La page ne montre pas de filtre par secteur | aucune | non |
| 3 | 2026-10-12 ≈05:39Z | SRC-020 | `www.ransomware.live/sectors` | chercher une vue du secteur de l'énergie | réponse HTTP 404 : page inexistante. Aucune donnée sectorielle obtenue | aucune | non |
| 4 | 2026-10-12 ≈05:40Z | SRC-021 | `attack.mitre.org/groups/G0046/` | confronter la piste du dossier (famille apparentée à Carbanak/FIN7) aux techniques documentées | FIN7 (alias GOLD NIAGARA, ITG14, Carbon Spider, ELBRUS, Sangria Tempest), lien possible avec Carbanak mais plusieurs groupes utilisent ce logiciel et sont suivis séparément. Accès initial : exploitation d'application exposée (T1190) puis hameçonnage (T1566). PowerShell (T1059.001) et tâche planifiée (T1053.005) figurent. L'extraction d'identifiants T1003 n'apparaît que via des logiciels associés ; la technique propre au groupe est Kerberoasting (T1558.003). Page modifiée le 31 juillet 2026 (version 4.1) | aucune | non |

## 4. Ce que cela change pour la mission

| Constat | Effet |
|---|---|
| Aucune des sources consultées ne contient une valeur du dossier (aucune n'a été interrogée avec une) | **aucun élément de dark web ne corrobore ni ne contredit un IoC** ; les cotes Admiralty des 40 IoC ne bougent pas |
| La page FIN7 confirme PowerShell et tâche planifiée, deux techniques observées | recoupement **non discriminant** : ces techniques sont communes à de nombreux groupes |
| La page FIN7 ne liste pas l'accès mémoire à LSASS (T1003.001) pour le groupe lui-même | **ne renforce pas** la piste du dossier ; point à relire sur la page complète avant tout usage. La conclusion reste **cluster non attribué** |
| Le suivi de sites de fuite ne montre aucune publication liée à la victime fictive (aucune recherche à son nom n'a été lancée, pour ne pas la diffuser) | absence de constat, pas constat d'absence |

## 5. Limites

- **Pas d'accès direct** au dark web : la consultation est indirecte, à travers des sources en clair. Elle ne remplace pas une veille directe, qui exigerait un cadre juridique, un poste isolé et un accord explicite.
- Les pages ont été lues par un outil de résumé automatique : les chiffres du suivi de fuites sont ceux affichés au moment de la lecture et n'ont pas été recoupés.
- Les sources 19 et 20 sont communautaires ou privées (cote C) ; la source 21 est officielle mais ses fiches de groupes reposent sur des rapports publics.
- Les IoC étant fictifs, aucune consultation ne pouvait aboutir à un résultat sur eux.

## 6. Modèle pour toute consultation ultérieure

Pour une consultation réelle, ajouter une ligne dans le tableau du §3 **et** dans [Journal-collecte.csv](Journal-collecte.csv) avant de lire la page suivante : date et heure UTC, source enregistrée, adresse, objectif, ce qui a été lu, « interaction : aucune », « donnée envoyée : non ». Toute interaction, inscription, message, achat ou téléchargement d'un fichier du marché est **interdit** ; en cas de doute, s'arrêter et demander.

Renvois : [Registre des sources](Registre-sources.csv) · [Journal de collecte](Journal-collecte.csv) · [Note d'attribution](../08-Rapports/Note-attribution.md) · [Hypothèses et attribution](../04-Analyse/Hypotheses-et-attribution.md)
