# Questions au commanditaire

Mise à jour : 2026-10-06. Les références B-xx renvoient à `Blocages-et-questions.md`. Priorité 1 = bloque une phase ; priorité 2 = améliore la qualité ; priorité 3 = confort.

## Priorité 1 : bloquantes

| # | Question | Pourquoi | Réf. |
|---|---|---|---|
| Q1 | Quel compte MISP utiliser et comment me transmettre la clé sans qu'elle apparaisse dans un livrable ? | Aucune lecture authentifiée ni ingestion possible | B-02 |
| Q2 | Acceptez-vous que je **lise** (secrets masqués) la configuration du connecteur MISP vers OpenCTI et de celui de TheHive pour déterminer ce qu'ils importent (événements publiés seulement, niveau de distribution, étiquettes, organisation du compte lecteur) ? Par quel accès ? | La distribution « organisation seulement » n'est **pas** une isolation prouvée : la documentation du vault ne mentionne aucun filtre. Sans cette lecture, aucune ingestion en production | B-03 |
| Q3 | Option d'isolement retenue : (a) instance ou organisation MISP séparée, (b) événement non publié en distribution 0 **sous réserve** du résultat de Q2, (c) pas d'ingestion | Choix du périmètre d'écriture | B-03 |
| Q4 | Puis-je créer un environnement Python dédié (`cti-helios-energy/.venv`) et y installer `stix2`, un validateur STIX, `pymisp`, `pysigma`, `networkx`, `matplotlib` ? | STIX, Sigma, graphe indisponibles | B-04 |

## Priorité 2 : qualité de l'analyse

| # | Question | Pourquoi | Réf. |
|---|---|---|---|
| Q5 | Les fiches tiennent-elles lieu des « 3 binaires » ? Existe-t-il un autre moyen d'obtenir les échantillons ou des sorties de bac à sable ? | Analyse statique impossible, empreintes non recalculables | B-01 |
| Q6 | Le fournisseur peut-il préciser les relations d'identifiants : D-01 à D-04, IP-07, IP-08, IP-09, CERT-01, HASH-STAGE vers les numéros du CSV ? | Les IP des fiches ne se rattachent pas au CSV | I-13 |
| Q7 | Le parent `winword.exe` de l'alerte 1 est-il correct alors que BIN-01 est un `.xlsm` ? | Contradiction I-18 | I-18 |
| Q8 | Qu'est-ce que 198.51.100.55 (alerte 6) : IP source réelle, pseudonymisation de l'IP de comptabilite-07, autre ? Et la source RDP de l'alerte 7 : interne ou 203.0.113.44 ? | Détermine si IOC-025/026 sont de l'infrastructure attaquante | I-04, I-05 |
| Q9 | Le compte `svc-backup-temp` existait-il avant le 5 mars ? Les horloges de srv-fichiers-02 et dc-01 sont-elles synchronisées ? Quel est le fuseau local du site ? | Contradiction I-03 | HYP-001/002 |
| Q10 | Le mémo a-t-il été mis à jour après sa date d'en-tête (2 mars) ? | Date anachronique | I-02 |
| Q11 | Peut-on obtenir les journaux complets (Sysmon 1, 8, 10 ; Security 4624, 4720, 4726, 4698 ; Zeek conn, ssl, notice ; Squid avec user-agent) ? | Les vérifications complémentaires de la matrice en dépendent | Matrice alertes |
| Q12 | Autorisez-vous des requêtes sur **documentation publique sans valeur d'IoC** (pages MITRE : déjà faites pour 17 techniques ; documentation Microsoft ; textes ANSSI) ? Et refusez-vous tout service de réputation tiers ? | Cadre de l'enrichissement ouvert | B-07 |

## Priorité 3 : organisation

| # | Question | Réf. |
|---|---|---|
| Q13 | Équipe (2 ou 3 personnes), rôles, dates réelles de travail, temps passé | B-05 |
| Q14 | Mode de comptage des « 25 objets » STIX : objets de domaine seuls ou avec relations et marquages ? | B-08 |
| Q15 | Confirmer la liste des 36 exigences obligatoires (le sujet officiel n'est pas dans le dossier) | B-10 |
| Q16 | Préciser, si connus, les SIIV et le secteur réglementaire d'Helios (le statut OIV est fourni par l'énoncé et n'est pas à confirmer) | B-11 |
| Q17 | Périmètre de test Wazuh isolé (machine, accès) ou abandon du volet optionnel | B-06 |
| Q18 | Emplacement du dépôt `cti-helios-energy` : proposition `~/Projet/cti-helios-energy/`, local, sans remote | B-09 |
| Q19 | Méthode d'analyse de risques pour la cartographie SI : EBIOS RM, ISO 27005, autre ? | REQ-21 |

## OpenCTI (ajout du 2026-10-06, voir `05-Plateformes/Plan-modelisation-OpenCTI.md`)

| # | Question | Priorité | Réf. |
|---|---|---|---|
| Q20 | Option d'écriture : **A** instance OpenCTI 6.9.21 locale jetable sur le Mac (recommandée ; démon Docker non vérifié, téléchargement d'images à confirmer), **B** production avec garde-fous, ou **C** Brouillon de la production ? | 1 | B-12, B-16 |
| Q21 | Si B : autorisez-vous la lecture des paramètres des connecteurs Google DNS, IPinfo, FIRST EPSS, du flux `jira` et des règles de déclin, puis la désactivation temporaire de l'enrichissement automatique ? | 1 | B-13, B-14 |
| Q22 | Quel compte OpenCTI utiliser pour écrire (compte dédié aux droits limités plutôt que l'administrateur principal) ? | 1 | B-15 |
| Q23 | Dates de l'incident : bornes d'observation (2026-03-02T08:31Z, 2026-03-07T09:02Z) avec avertissement, ou champs vides ? | 2 | |
| Q24 | Validez-vous les comptages (Analyses 11, Événements 9, Observations 40), les 8 indicateurs, les 4 sightings conditionnels et les exclusions ? | 2 | |

## Questions restantes en fin de session

| # | Question | Priorité |
|---|---|---|
| Q25 | Voulez-vous contrôler vous-même les interfaces (OpenCTI, MISP, dashboard Wazuh) avec les liens et filtres du guide, et me communiquer les écarts ? | 1 |
| Q26 | Faut-il retirer les objets de test des plateformes (OpenCTI : label `challenge:helios-fictif` ; MISP : événement 6, organisation 2, utilisateur 5 ; Wazuh : 2 fichiers, alertes `helios_challenge`) ? Aucune suppression n'a été faite sans votre demande. | 1 |
| Q27 | Confirmez-vous le principe d'une écriture avec le jeton d'administration d'OpenCTI, ou souhaitez-vous un compte restreint pour la suite ? | 2 |
| Q28 | Les connecteurs MISP vers OpenCTI doivent-ils recevoir un filtre d'exclusion de l'organisation CHALLENGE-FICTIF avant la reprise de leur file ? | 2 |
| Q29 | Écart de marquage : MISP en `tlp:amber`, OpenCTI en TLP:RED. Quel niveau retenir (aligner MISP sur RED, ou OpenCTI sur AMBER) ? | 1 |
| Q30 | Les 3 organisations de support OpenCTI n'ont ni étiquette ni marquage : autorisez-vous à leur ajouter l'étiquette `challenge:helios-fictif` et le marquage TLP:RED (3 écritures) ? | 2 |
| Q31 | Dépôt Git `cti-helios-energy` (obligatoire) : **réponse du 2026-10-07 : l'utilisateur le crée lui-même** ; reste à me faire relancer `verify` sur le dépôt créé pour passer REQ-36 à VALIDÉ | 1 |
| Q32 | Date de début de validité des indicateurs : la première alerte qui les porte (choix fait dans le bundle local) vous convient-elle ? Faut-il l'appliquer aussi dans OpenCTI (8 mises à jour) ? | 3 |
