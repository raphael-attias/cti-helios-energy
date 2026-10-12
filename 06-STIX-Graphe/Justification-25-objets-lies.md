# Justification : au moins 25 objets STIX liés

Généré par `06-STIX-Graphe/generer-liaison-stix.py` depuis `Bundle-STIX.json` (152 objets). Inventaire ligne à ligne : `Inventaire-liaison-STIX.csv`. **Cette méthode est un choix de vérification conservateur de l'équipe, pas une règle imposée par le commanditaire** ; la définition de « objets liés » n'a pas été fournie (RFI-05).

## 1. Résultat

**27 objets de renseignement distincts, tous reliés dans une seule composante connexe** (celle de la campagne « cluster non attribué », 42 objets au total avec les observables, identités et données observées atteints par une relation). Seuil de 25 : **ATTEINT**. Sensibilité : en retirant les 2 objets ajoutés dont la seule base est le texte d'une alerte (statut hypothèse ou déclaré), il en reste **25** (seuil toujours atteint). En ajoutant les 4 actifs victimes (comptés à part) : 31.

| Catégorie (jamais mélangées) | Nombre | Dans le comptage ? |
|---|---|---|
| **Objets de renseignement** : attack-pattern 8, campaign 1, indicator 8, infrastructure 4, malware 3, tool 3 | **27** | **oui** |
| Actifs victimes (identités : organisation et 3 systèmes) | 4 | non (comptés à part) |
| Observables (SCO) | 39 | non |
| Données observées (conteneurs d'observation) | 28 | non |
| Relations (based-on 8, consists-of 5, indicates 8, related-to 1, targets 4, uses 18) | 44 | **jamais comptées comme entités** |
| Conteneurs (rapport, regroupement, notes) | 7 | non |
| Identités d'auteur, marquage, objets techniques | 3 | non |

Statuts des 27 objets comptés : declare 7, hypothese 6, non-attribue 1, observe 13 (le statut est écrit dans chaque objet : un objet « hypothèse » ou « déclaré » est un objet de renseignement étiqueté comme tel, pas une observation).

## 2. Pourquoi 20, 24, 34, 99 (avant les ajouts), et 27 maintenant

| Comptage | Définition | Avant T13 | Après T13 |
|---|---|---|---|
| **Principal (M)** | objets de renseignement (campagne, malware, outil, infrastructure, technique, indicateur) extrémités d'une relation, dans la composante de la campagne | n/a | **27** |
| C (ancienne définition conservatrice) | mêmes types sans `tool` ni `infrastructure` | 20 | 20 |
| B | C et les 4 actifs victimes | 24 | 24 |
| A | tout objet (hors relation) extrémité d'une relation (ajoute observables et données observées reliés) | 34 | 42 |
| D | A et tout objet référencé par un conteneur ou une donnée observée (hors relations et marquage) | 99 | 106 |

Les écarts viennent des objets réels : A ajoute à B les observables atteints par un `based-on` ou un `consists-of` et les données observées reliées ; D ajoute tout ce que le rapport, le regroupement, les notes et les données observées référencent. **Les relations et marquages ne sont jamais comptés comme entités** dans la méthode principale.

## 3. Ajouts T13 (2026-10-07) : preuve et justification

Les 20 objets d'analyse d'origine étaient justifiés par les alertes et fiches (voir leurs lignes ci-dessous). Une recherche des éléments prouvés mais omis a donné **7 ajouts**, chacun relié à la campagne ; **aucun malware, acteur ou échantillon n'a été ajouté**, aucun découpage artificiel (un objet par rôle ou par logiciel distinct cité).

| Ajout | Preuve | Statut | Pourquoi ce n'est pas un doublon |
|---|---|---|---|
| tool `powershell.exe` | journal brut ligne 1 : `winword.exe -> powershell.exe -enc ... -w hidden` (alerte 1) | observé | la technique T1059.001 décrit un comportement ; l'outil est le logiciel nommé dans la ligne de commande |
| tool `wevtutil.exe` | journal brut ligne 12 : `1102 audit log cleared / wevtutil cl Security` (alerte 12) | observé | idem pour T1685.005 |
| tool `schtasks.exe` | détail de l'alerte 3 seulement (`schtasks /create`) ; **absent du journal brut (I-20)** | déclaré | idem pour T1053.005 |
| infrastructure : hébergement du téléchargement (cdn-svc-update.test) | alerte 2, journal ligne 2 : GET 200 de 421376 octets ; IOC-013, IOC-029 | observé | un rôle réseau (hôte de la seconde charge), distinct de l'indicateur qui n'est qu'un motif de détection |
| infrastructure : destination de la balise (198.51.100.24) | alerte 4, journal ligne 4 : une connexion vers :443 ; IOC-020 | observé (périodicité non démontrée) | idem pour le rôle de balise |
| infrastructure : destination de la sortie (203.0.113.28) | alerte 10, journal ligne 10 : 2 469 135 790 octets vers :8080 ; IOC-024 | observé | idem pour la sortie de données |
| infrastructure : repli supposé (static-assets-cache.test) | alerte 11, journal ligne 11 ; **rôle contredit par I-11** | hypothèse | rôle de repli distinct des trois autres ; étiqueté hypothèse |

Relations ajoutées : 7 `uses` depuis la campagne (3 outils, 4 infrastructures) et 5 `consists-of` de chaque infrastructure vers les observables déjà présents (domaines, URL, adresses). Aucune relation n'a été créée pour l'apparence : chacune dit un fait ou une hypothèse étiquetée prouvé par la ligne citée. Les 4 infrastructures ne reprennent pas les relations `indicates` des indicateurs (elles ne sont pas démontrées par un artefact).

**Éléments cherchés et NON ajoutés, faute de preuve** : les techniques seulement probables (T1003.001, T1071.001, T1008, T1048.003, T1136.002, T1078, T1543.003) ; un `intrusion-set` ou une famille de malware (aucun élément indépendant) ; des indicateurs pour les 32 autres IoC déclarés non vérifiés ; `rundll32.exe` (le processus hôte de la DLL n'est pas nommé, I-08) ; `explorer.exe` (cible d'injection, pas un outil de l'attaquant) ; des `course-of-action` (recommandations de l'équipe, pas des faits des artefacts).

## 4. Les 27 objets comptés et leurs preuves

| Identifiant | Type | Nom | Statut | Source dans les artefacts | Relations |
|---|---|---|---|---|---|
| `attack-pattern--79e532…` | attack-pattern | Clear Windows Event Logs | observe | technique T1685.005 : https://attack.mitre.org (vérifiée, voir 04-Analyse/Version-ATTACK.md) | 1 |
| `attack-pattern--da4eae…` | attack-pattern | Hidden Window | observe | technique T1564.003 : https://attack.mitre.org (vérifiée, voir 04-Analyse/Version-ATTACK.md) | 1 |
| `attack-pattern--40d5a6…` | attack-pattern | Ingress Tool Transfer | observe | technique T1105 : https://attack.mitre.org (vérifiée, voir 04-Analyse/Version-ATTACK.md) | 1 |
| `attack-pattern--a7cb07…` | attack-pattern | Network Service Discovery | observe | technique T1046 : https://attack.mitre.org (vérifiée, voir 04-Analyse/Version-ATTACK.md) | 1 |
| `attack-pattern--905a0b…` | attack-pattern | PowerShell | observe | fourniture/05_journaux_bruts.log ligne 1 ; technique T1059.001 : https://attack.mitre.org (vérifiée, voir 04-Analyse/Version-ATTACK.md) | 1 |
| `attack-pattern--ed86fc…` | attack-pattern | Process Injection | observe | technique T1055 : https://attack.mitre.org (vérifiée, voir 04-Analyse/Version-ATTACK.md) | 1 |
| `attack-pattern--47a264…` | attack-pattern | Remote Desktop Protocol | observe | technique T1021.001 : https://attack.mitre.org (vérifiée, voir 04-Analyse/Version-ATTACK.md) | 1 |
| `attack-pattern--447578…` | attack-pattern | Scheduled Task | observe | technique T1053.005 : https://attack.mitre.org (vérifiée, voir 04-Analyse/Version-ATTACK.md) | 1 |
| `campaign--00ef2a8a-20a…` | campaign | [CHALLENGE FICTIF] Cluster non attribué INC-2026-0302 | non-attribue | synthèse de l'équipe (aucun artefact unique) | 30 |
| `indicator--10b593bb-4d…` | indicator | [CHALLENGE FICTIF] IND-01 BIN-001 dropper (fiche) | declare | fourniture/01_fiches_analyse_binaires.md ; fourniture/02_indicateurs_40.csv (IOC-001) | 2 |
| `indicator--5ab5b839-ef…` | indicator | [CHALLENGE FICTIF] IND-02 BIN-002 balise (fiche) | declare | fourniture/05_journaux_bruts.log ligne 2 ; fourniture/01_fiches_analyse_binaires.md ; fourniture/02_indicateurs_40.csv (IOC-004) | 2 |
| `indicator--d7c48f42-80…` | indicator | [CHALLENGE FICTIF] IND-03 BIN-003 outil d'identifiants (fiche) | declare | fourniture/01_fiches_analyse_binaires.md ; fourniture/02_indicateurs_40.csv (IOC-007) | 2 |
| `indicator--807c3cbe-6d…` | indicator | [CHALLENGE FICTIF] IND-04 domaine de téléchargement de BIN-002 | hypothese | fourniture/03_alertes_siem_12.csv alerte 2 ; fourniture/05_journaux_bruts.log ligne 2 ; fourniture/02_indicateurs_40.csv (IOC-013) | 2 |
| `indicator--57b691c7-a8…` | indicator | [CHALLENGE FICTIF] IND-05 URL de la seconde charge | hypothese | fourniture/03_alertes_siem_12.csv alerte 2 ; fourniture/05_journaux_bruts.log ligne 2 ; fourniture/02_indicateurs_40.csv (IOC-029) | 2 |
| `indicator--d32ff7bb-74…` | indicator | [CHALLENGE FICTIF] IND-06 destination de la connexion de balise (ALERT | hypothese | fourniture/03_alertes_siem_12.csv alerte 4 ; fourniture/05_journaux_bruts.log ligne 4 ; fourniture/02_indicateurs_40.csv (IOC-020) | 2 |
| `indicator--97897198-77…` | indicator | [CHALLENGE FICTIF] IND-07 destination de la sortie de 2 469 135 790 oc | hypothese | fourniture/03_alertes_siem_12.csv alerte 10 ; fourniture/05_journaux_bruts.log ligne 10 ; fourniture/02_indicateurs_40.csv (IOC-024) | 2 |
| `indicator--8a932155-1d…` | indicator | [CHALLENGE FICTIF] IND-08 domaine du « repli C2 » (ALERT-011) | hypothese | fourniture/03_alertes_siem_12.csv alerte 11 ; fourniture/05_journaux_bruts.log ligne 11 ; fourniture/02_indicateurs_40.csv (IOC-016) | 2 |
| `infrastructure--e421b9…` | infrastructure | [CHALLENGE FICTIF] Destination de la connexion de balise (198.51.100.2 | observe | fourniture/03_alertes_siem_12.csv alerte 4 ; fourniture/05_journaux_bruts.log ligne 4 ; fourniture/02_indicateurs_40.csv (IOC-020) | 2 |
| `infrastructure--f19e05…` | infrastructure | [CHALLENGE FICTIF] Destination de la sortie de données (203.0.113.28) | observe | fourniture/03_alertes_siem_12.csv alerte 10 ; fourniture/05_journaux_bruts.log ligne 10 ; fourniture/02_indicateurs_40.csv (IOC-024) | 2 |
| `infrastructure--0062c1…` | infrastructure | [CHALLENGE FICTIF] Hébergement du téléchargement (cdn-svc-update.test) | observe | fourniture/03_alertes_siem_12.csv alerte 2 ; fourniture/05_journaux_bruts.log ligne 2 ; fourniture/02_indicateurs_40.csv (IOC-013) ; fourniture/02_ind | 3 |
| `infrastructure--36b67c…` | infrastructure | [CHALLENGE FICTIF] Repli de commande supposé (static-assets-cache.test | hypothese | fourniture/03_alertes_siem_12.csv alerte 11 ; fourniture/05_journaux_bruts.log ligne 11 ; fourniture/02_indicateurs_40.csv (IOC-016) | 2 |
| `malware--217f1232-8d80…` | malware | facture_mars_2026.xlsm (BIN-001) | declare | fourniture/01_fiches_analyse_binaires.md | 1 |
| `malware--fd879985-6c14…` | malware | rundll32_helper.dll (BIN-003) | declare | fourniture/01_fiches_analyse_binaires.md | 1 |
| `malware--e1d16652-f5c7…` | malware | svchost_update.exe (BIN-002) | declare | fourniture/01_fiches_analyse_binaires.md | 1 |
| `tool--aaa894f0-e340-52…` | tool | powershell.exe | observe | fourniture/03_alertes_siem_12.csv alerte 1 ; fourniture/05_journaux_bruts.log ligne 1 | 1 |
| `tool--09560a4d-4ab5-5a…` | tool | schtasks.exe | declare | fourniture/03_alertes_siem_12.csv alerte 3 | 1 |
| `tool--49a696f7-0695-5a…` | tool | wevtutil.exe | observe | fourniture/03_alertes_siem_12.csv alerte 12 ; fourniture/05_journaux_bruts.log ligne 12 | 1 |


## 5. Actifs victimes (comptés à part)

| Identifiant | Type | Nom | Statut | Source dans les artefacts | Relations |
|---|---|---|---|---|---|
| `identity--9ecaad58-3b6…` | identity | Helios Energy (fictif) | n/a | énoncé du sujet (victime) ; hôtes cités par les alertes et le journal brut | 1 |
| `identity--fc4c54fc-d12…` | identity | comptabilite-07 | n/a | énoncé du sujet (victime) ; hôtes cités par les alertes et le journal brut | 1 |
| `identity--ddc7687d-677…` | identity | dc-01 | n/a | énoncé du sujet (victime) ; hôtes cités par les alertes et le journal brut | 1 |
| `identity--a39cef96-0c3…` | identity | srv-fichiers-02 | n/a | énoncé du sujet (victime) ; hôtes cités par les alertes et le journal brut | 1 |


## 6. Objets exclus du comptage principal, et pourquoi

| Catégorie | Nombre | Exemple | Pourquoi exclus |
|---|---|---|---|
| Observables (SCO) | 39 | adresses, domaines, URL, hashes de fichier | des valeurs, pas des objets d'analyse ; atteints par `based-on` et `consists-of` |
| Données observées | 28 | observation d'un fichier ou d'un domaine | conteneurs d'observation |
| Relations | 44 | `uses`, `targets`, `indicates`, `based-on`, `consists-of`, `related-to` | jamais des entités |
| Conteneurs, identités d'auteur, marquage | 10 | rapport, regroupement, 5 notes, 2 identités d'auteur, TLP | techniques ou documentaires |

Détail objet par objet (types, relations entrantes et sortantes, autres références, composante, inclusion et justification) : `Inventaire-liaison-STIX.csv`.

## 7. Procédure reproductible de comptage

1. `bash 11-Validation/regenerer-stix.sh` (construit le bundle, le valide, génère le graphe, l'inventaire et ce document) ou, pour le seul comptage : `/Users/rapatt/Projet/cti-helios-env/.venv/bin/python 06-STIX-Graphe/generer-liaison-stix.py`.
2. Le script lit `Bundle-STIX.json`, construit le graphe non orienté des relations (`relationship`), prend la composante de la campagne et retient les objets de type campaign, malware, tool, infrastructure, attack-pattern et indicator qui y figurent.
3. Contrôle : `11-Validation/controles-exigences.py` (REQ-15) recompte indépendamment depuis le bundle et compare à `Liaison-STIX.json`.
4. Équivalent à la main : `jq '[.objects[] | select(.type|IN("campaign","malware","tool","infrastructure","attack-pattern","indicator"))] | length' Bundle-STIX.json` donne 27 objets de ces types ; tous sont reliés par au moins une relation et appartiennent à la composante de la campagne (oui).

## 8. Cohérence avec MISP et OpenCTI, et corrections externes

| Plateforme | État | Correction préparée |
|---|---|---|
| MISP | l'événement 6 ne contient ni `tool` ni `infrastructure` (aucun type de ce nom dans le modèle d'objets utilisé) ; les objets d'analyse (campagne, malwares, indicateurs, techniques sous forme de galaxies) n'y sont déjà que partiellement | **aucune** : écart documenté (`Ecarts-bundle-plateformes.md`, E12) |
| OpenCTI | l'incident remplace la campagne ; ni infrastructure ni outil | création de 4 `Infrastructure` et liaison à 3 outils existants : préparée dans `05-Plateformes/octi_stix_complements.py` (mode plan en lecture seule), **non appliquée sans approbation** |

## 9. Limites

La méthode compte des objets de statuts différents (observé, déclaré, hypothèse) : elle démontre 25 objets de renseignement justifiés et étiquetés, pas 25 observations. La définition de « lié » n'a pas été confirmée par le commanditaire. Le bundle reste dérivé de l'export MISP et enrichi localement, pas un export pur. Les ajouts T13 existent dans le bundle ; leur présence dans OpenCTI dépend d'une approbation.
