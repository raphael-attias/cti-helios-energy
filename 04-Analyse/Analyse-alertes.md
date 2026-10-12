# Analyse des 12 alertes SIEM

Date : 2026-10-06. Statut : **analyse de l'équipe, non relue par un tiers**. Elle ne couvre que les alertes et leur journal brut ; les fiches de binaires et les IoC ne sont pas analysés ici.

Matrice complète (une ligne par alerte, 22 colonnes) : `Matrice-analyse-alertes.csv`. Techniques vérifiées : `Matrice-ATTACK.csv`. Chronologie : `Chronologie.csv`. Tout est régénéré par `generer-analyse-alertes.py`, qui **relit chaque preuve citée dans les originaux** (29 extraits contrôlés, 0 introuvable : sortie archivée dans `sortie-generer-analyse-alertes.txt`).

## 1. Méthode

1. Pour chaque alerte, la ligne du journal brut est retrouvée par horodatage et hôte. Le journal est trié par date, **pas** dans l'ordre des alertes : l'alerte 5 correspond à la ligne 8 du journal, les alertes 6, 7, 8 aux lignes 5, 6, 7.
2. La technique ATT&CK du SIEM n'est **pas** reprise : chaque technique est reconstruite à partir de ce que la ligne montre, puis son identifiant et son nom sont comparés à la page officielle (outil WebFetch, 2026-10-06). Résultat : 10 techniques du SIEM sont retenues après examen de la preuve, 2 sont écartées (alerte 8 : T1055.012 ; alerte 9 : T1543.003) et des techniques complémentaires sont proposées (voir matrice).
3. Vocabulaire : OBSERVÉ (présent dans l'artefact), CORROBORÉ (confirmé par un second artefact, sans prétendre à l'indépendance), HYPOTHÈSE, INCONNU. Les niveaux de confiance (faible, moyenne, élevée) sont ceux de l'analyste et **ne sont pas des cotes Admiralty**.
4. Les originaux ne sont jamais corrigés (dates, adresses IP). Les lectures alternatives sont des hypothèses numérotées avec leur impact.

**Limites de la vérification ATT&CK** : les versions et dates viennent de pages résumées par l'outil de lecture, à reconfirmer visuellement. **T1070.001** (alerte 12) n'a pas pu être récupéré (3 échecs) : son nom est écrit de mémoire et marqué NON VÉRIFIÉ. Les événements Windows (4624 type 10, 4720, 4726, 1102) sont interprétés d'après la connaissance générale ; la documentation Microsoft n'a pas été consultée.

## 2. Alerte 8 en détail (T1055.012 contesté)

| Élément | Contenu |
|---|---|
| Libellé original (`03_alertes_siem_12.csv`, ligne 9) | « Injection de code dans un processus légitime » ; technique du SIEM T1055.012 ; sévérité Haute ; détail « explorer.exe présente une région mémoire exécutable anormale » |
| Ligne exacte (`05_journaux_bruts.log`, ligne 7) | `2026-03-04T11:05:00Z srv-fichiers-02 Sysmon: CreateRemoteThread into explorer.exe RWX region` |
| Pourquoi je conteste T1055.012 | La page ATT&CK (Process Injection : Process Hollowing, version 2.0 lue) décrit la création d'un **nouveau** processus en état suspendu dont la mémoire est vidée puis remplacée, et précise qu'il ne s'agit pas de cibler un processus déjà en cours. La ligne montre un thread distant créé **dans** explorer.exe, avec une région RWX. Rien n'indique un processus créé suspendu ni un remplacement de mémoire. |
| Ce que ATT&CK dit de CreateRemoteThread | La page T1055.001 (DLL Injection) le cite comme moyen d'invocation ; la page T1055.002 (PE Injection) décrit l'exécution par de nouveaux threads. La ligne ne départage pas ces deux sous-techniques. |
| Ce que l'artefact permet de conclure | Sur srv-fichiers-02, le 2026-03-04 à 11:05Z, un thread distant a été créé dans explorer.exe, avec une région mémoire RWX. C'est un **indice d'injection de code** : T1055 au niveau de la technique parente, confiance élevée pour ce constat. |
| Ce qui reste non démontré | Process Hollowing ; la sous-technique (001 ou 002) ; l'initiateur (aucune image source) ; que l'initiateur soit BIN-002 (seul IOC-011, **déclaré** par le SOC, le suggère) ; la nature et l'effet du code injecté ; que BIN-002 soit présent sur srv-fichiers-02 ; la manière dont l'attaquant est arrivé sur ce serveur. |
| Réserves | La fiche BIN-02 parle de « creux de processus » dans explorer.exe : description ambiguë vis-à-vis de la définition ATT&CK, à lever avec l'échantillon (non fourni). Le champ « RWX region » n'est pas, à ma connaissance, un champ standard d'un événement Sysmon 8 : la ligne semble résumée ou enrichie. |

## 3. Trois catégories séparées

### 3.1 Anomalies de qualité ou de cohérence des données

À traiter comme des défauts du dossier, pas comme des indices contre l'attaquant. Le détail des 17 premières est dans `02-Artefacts/Integrite-et-provenance.md` ; quatre s'ajoutent à l'analyse des alertes :

| ID | Anomalie | Alertes | Impact sur l'analyse |
|---|---|---|---|
| I-03 | `svc-backup-temp` ouvre une session RDP (4 mars 01:47) 36 h avant sa création (5 mars 14:12) | 7, 9 | Bascule le raisonnement sur l'origine du premier accès à srv-fichiers-02 ; voir HYP-001, HYP-002, HYP-012 |
| I-04 | Source du RDP : « interne » (alerte) vs IP externe 203.0.113.44 (IOC-026) | 7 | Vecteur d'accès inconnu ; IOC-026 non exploitable en blocage tant que non tranché |
| I-05 | Une IP de plage de documentation (198.51.100.55) « scanne » un /16 interne | 6 | Décide si IOC-025 est de l'infrastructure attaquante ou un actif victime (HYP-003, HYP-004) |
| I-06 | T1055.012 vs CreateRemoteThread | 8 | Voir section 2 |
| I-07 | BIN-002 récupéré sur comptabilite-07, injection sur srv-fichiers-02 | 8, 11 | Mouvement latéral et présence de BIN-002 sur le serveur : non démontrés |
| I-08 | « by rundll32_helper.dll » : une DLL n'est pas un processus | 5 | Initiateur réel du handle inconnu |
| I-09 | Création 14:10 (détail, IOC-037) vs 14:12 (journal) ; suppression 14:55 vs 14:57 | 9 | Mineur |
| I-10 | « 2,3 Go » vs 2 469 135 790 octets | 10 | Utiliser les octets |
| I-11 | Repli connu le 3 mars, utilisé le 6 mars | 11 | Datation de la découverte vs de l'usage |
| I-12 | Deux C2 distincts (198.51.100.24 vs 203.0.113.14) | 4 | Rôle de chaque IP à établir |
| I-18 (nouvelle) | Parent `winword.exe` alors que BIN-01 est un classeur `.xlsm` (Excel) | 1 | Soit le parent est mal étiqueté, soit l'artefact initial n'est pas celui décrit ; ne pas supposer |
| I-19 (nouvelle) | Alerte 12 titrée « tentative » alors que 1102 atteste un effacement effectif | 12 | Perte probable de journaux Security de comptabilite-07 |
| I-20 (nouvelle) | Alerte 3 : commande schtasks dans l'alerte mais absente du journal brut ; libellé « Sysmon: Scheduled Task Created » non standard | 3 | Origine réelle du journal inconnue (limite) |
| I-21 (nouvelle) | Éléments de détail d'alerte absents des lignes brutes : « non signé » (5), « source interne inhabituelle » (7), « toutes les ~300 s » (4), « après perte du C2 principal » (11) | 4, 5, 7, 11 | Le détail du SIEM ne doit pas être traité comme preuve brute |

### 3.2 Indices de compromission (observations dans les artefacts)

| ID | Observation | Alerte | Artefact |
|---|---|---|---|
| OBS-001 | winword.exe parent de powershell.exe avec `-enc` (décodage du préfixe : IEX) et `-w hidden` | 1 | journal ligne 1 |
| OBS-002 | Téléchargement HTTP 200 de 421376 octets depuis `cdn-svc-update.test/win/svchost_update.exe` | 2 | journal ligne 2 |
| OBS-003 | Création de la tâche `MicrosoftEdgeUpdateTaskMachine` | 3 | journal ligne 3 |
| OBS-004 | Une connexion de 0,4 s et 812 octets vers 198.51.100.24:443, étiquetée « beacon » | 4 | journal ligne 4 |
| OBS-005 | Balayage Zeek de 10.20.0.0/16 sur 445 et 3389 par 198.51.100.55 | 6 | journal ligne 5 |
| OBS-006 | 4624 type 10 pour `svc-backup-temp` sur srv-fichiers-02 | 7 | journal ligne 6 |
| OBS-007 | Thread distant dans explorer.exe, région RWX, sur srv-fichiers-02 | 8 | journal ligne 7 |
| OBS-008 | Accès à lsass.exe avec le masque 0x1010 (lecture de la mémoire) | 5 | journal ligne 8 |
| OBS-009 | 4720 (création) puis 4726 (suppression) de `svc-backup-temp` sur dc-01 | 9 | journal ligne 9 |
| OBS-010 | Sortie de 2 469 135 790 octets vers 203.0.113.28:8080 en clair depuis dc-01 | 10 | journal ligne 10 |
| OBS-011 | GET 200 vers `static-assets-cache.test` annoté « failover C2 » | 11 | journal ligne 11 |
| OBS-012 | 1102 et `wevtutil cl Security` sur comptabilite-07 | 12 | journal ligne 12 |

Corroborations (entre artefacts du même fournisseur, donc non indépendantes) : taille 421376 (journal ligne 2 et fiche BIN-02) ; empreintes des fiches présentes dans le CSV des IoC.

### 3.3 Hypothèses d'investigation (non démontrées)

| ID | Hypothèse | Ce qui la soutient | Ce qui la contredit ou manque | Impact si vraie |
|---|---|---|---|---|
| HYP-001 | `svc-backup-temp` préexistait ; le 4720 du 5 mars est une recréation | Session RDP du 4 mars | Aucun événement antérieur | Le vol LSASS n'est pas la source de ce compte ; intrusion antérieure ou autre voie |
| HYP-002 | Horloges ou fuseaux désalignés entre srv-fichiers-02 et dc-01 | Écart de 36 h inexpliqué | Les autres événements restent cohérents en séquence | Toute la chronologie inter-hôtes est à reprendre |
| HYP-003 | 198.51.100.55 est une pseudonymisation de l'IP interne de comptabilite-07 | Journal émis par comptabilite-07 ; IOC-025 « depuis poste compromis » | Aucune table de correspondance fournie | IOC-025 n'est pas un indicateur offensif ; ne pas bloquer ni diffuser comme tel |
| HYP-004 | Scanneur externe atteignant le /16 | IP publique, ports 445/3389 | Mention « interne » dans l'alerte et l'IoC | Vecteur d'entrée alternatif, périmètre de confinement différent |
| HYP-005 | BIN-002 est présent sur srv-fichiers-02 et responsable de l'injection et du repli | IOC-011 (« module injecté par BIN-02 ») | Aucun lien technique, échantillon absent | Étend l'impact de comptabilite-07 à un serveur de fichiers |
| HYP-006 | Injection de PE ou de code (région RWX) plutôt que simple DLL | Région RWX | Rien sur le contenu | Choix de la règle de détection |
| HYP-007 | Les données exfiltrées viennent des serveurs de fichiers via dc-01 | Mémo | Aucun lien d'artefact entre les deux | Étendue des données à rechercher sur les serveurs de fichiers |
| HYP-008 | L'attaquant était encore présent le 7 mars | Effacement des journaux le 7 mars | Un script automatique est possible | Confinement incomplet ; surveillance renforcée |
| HYP-009 | Le SIEM confond compte de service et service Windows | Libellé de l'alerte 9 et T1543.003 | Fiche BIN-03 évoque aussi un service | Mapping ATT&CK de l'alerte 9 à corriger |
| HYP-010 | Le proxy intercepte TLS (URL HTTPS visible) | URL complète dans Squid | Configuration inconnue | Visibilité réelle sur les flux chiffrés |
| HYP-011 | La date du mémo n'est pas celle de sa rédaction initiale | Mémo daté du 2 mars décrivant des faits du 5 au 7 mars | Aucune version antérieure | Ne pas citer le mémo comme source contemporaine des faits |
| HYP-012 | L'événement RDP du 4 mars est une donnée mal alignée | Contradiction avec la création | Cohérence de l'IoC 26 | Perdre une pièce de la chaîne latérale |

## 4. Corrélations entre alertes (nature du lien)

| Lien | Nature | Statut |
|---|---|---|
| 1 → 2 → 3 (08:31, 08:42, 08:46, même hôte) | Lien temporel ; causalité plausible | CORROBORÉ par la fiche BIN-01/02, non prouvé |
| 3 → 4 (balise 30 min plus tard) | Lien temporel | Hypothèse |
| 6 (balayage 445/3389) → 7 (RDP) | Lien temporel et de port, 15 h 35 d'écart | Hypothèse |
| 5 → 9 → 10 (14:07, 14:12, 15:31, dc-01) | Lien temporel ; lien d'artefact déclaré par la fiche BIN-03 | Hypothèse forte |
| 7 et 9 (même compte) | Égalité exacte du nom de compte | OBSERVÉ, mais chronologie contradictoire (I-03) |
| 4 et 11 (C2 principal et repli) | Relation réseau et certificat **déclarée** (IOC-016, IOC-033) | Non étayée par un artefact |
| 8 et 11 (même hôte srv-fichiers-02) | Cooccurrence d'hôte | Pas de lien causal établi |
| 12 (effacement) et 1 à 4 (poste d'entrée) | Même hôte | Impact : perte de traces sur cet hôte |

## 5. Impact des lectures alternatives sur la suite

- **Inventaire des IoC** : IOC-025 (HYP-003/004) et IOC-026 (I-04) doivent rester **non diffusables comme indicateurs offensifs** tant que leur nature n'est pas établie. Le manifeste MISP les marque déjà `to_ids=false`.
- **Chronologie** : HYP-001/002 peuvent déplacer les événements de srv-fichiers-02 de plusieurs heures ou jours. La chronologie reste sous cette incertitude (`Chronologie.csv`).
- **Règles Sigma** : l'alerte 8 oriente vers une détection de thread distant dans explorer.exe (Sysmon 8), pas vers une détection de Process Hollowing ; l'alerte 9 vers 4720 sur DC plutôt que vers la création de service.
- **Attribution** : aucun élément de ces alertes ne désigne un groupe. Voir `Indication-dossier-pedagogique.md`.
- **Impact sur les actifs** : la matrice CID ne retiendra comme « touchés » que comptabilite-07, dc-01 et srv-fichiers-02, avec impact **observé** limité aux événements ci-dessus.

## 6. Limites finales de l'analyse des alertes

Toutes les vérifications complémentaires listées dans la dernière colonne de la matrice exigent des données hors dossier (journaux complets, annuaire, PCAP). Elles ont été demandées dans les RFI-02 et RFI-04 (ouvertes, sans réponse) : ce sont des limites définitives de l'analyse, pas des travaux restants.
