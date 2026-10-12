# Exigences : origine, périmètre et réconciliation 35 vers 36

Date : 2026-10-06. Généré par `11-Validation/generer-exigences-origine.py`.

**Réserve de départ (B-10)** : le sujet officiel n'est pas dans le dossier. La liste ci-dessous est ma lecture du **brief du commanditaire** (première instruction de la mission, numérotée §1 à §15) et du LISEZ-MOI fourni. Le dépôt `cti-helios-energy` est obligatoire depuis le sujet initial (confirmé par le commanditaire). Q15 reste ouverte : confirmer cette liste.

## 1. Pourquoi 35 puis 36

| Étape | Dénominateur officiel | Ce qui s'est passé |
|---|---|---|
| Début de session | 36 (REQ-01 à REQ-36) | l'ancien REQ-36 était « consultation OpenCTI en trois rubriques » : **demande supplémentaire et non exigence du sujet** ; le dépôt Git était classé à tort optionnel (OPT-06) |
| Fin de session initiale | **35** | l'ancien REQ-36 sorti du périmètre officiel (devenu SUP-01) ; le dépôt restait **classé à tort comme optionnel** |
| Revue de clôture | **36** | correction d'une **erreur de classement de ma part** : le dépôt est obligatoire depuis le sujet initial, OPT-06 devient **REQ-36** |

Le dénominateur n'a pas été ajusté pour améliorer un pourcentage : la correction **ajoute** une exigence non satisfaite (dépôt non créé) et fait baisser le ratio. Les deux « 36 » ne désignent pas le même objet (ancien REQ-36 = OpenCTI ; REQ-36 actuel = Git). Le 35 était donc une sous-estimation, le 36 actuel est le total cohérent avec le sujet.

## 2. Exigences obligatoires du sujet (36)

| ID | Exigence | Origine | Statut technique | Contrôles | Relecture humaine nécessaire |
|---|---|---|---|---|---|
| REQ-01 | Inventaire des 40 IoC, comptages séparés | brief §6 (inventaire, 40 IoC annoncés) ; §5 `Inventaire-IoC.csv` | SATISFAIT ET CONTRÔLÉ | voir preuve | non |
| REQ-02 | Inventaire des 12 alertes | brief §6 (12 alertes) ; §5 `Inventaire-alertes.csv` | SATISFAIT ET CONTRÔLÉ | voir preuve | non |
| REQ-03 | Inventaire des 3 fiches binaires | brief §6 (3 binaires) ; §5 `Inventaire-binaires.csv` | SATISFAIT ET CONTRÔLÉ | voir preuve | non |
| REQ-04 | Vérification des empreintes et analyse statique des 3 binaires | brief §6 (« vérifie les empreintes, analyses statiques accessibles ») ; LISEZ-MOI : échantillons non fournis | NON SATISFAIT | voir preuve | non |
| REQ-05 | Intégrité et provenance | brief §5 `Integrite-et-provenance.md`, §6 (traçabilité, hash) | SATISFAIT ET CONTRÔLÉ | 5/5 OK | oui : interprétation des 21 incohérences |
| REQ-06 | Registre des sources et journal de collecte | brief §5 `Registre-sources.csv`, `Journal-collecte.csv` | SATISFAIT ET CONTRÔLÉ | 3/3 OK | non |
| REQ-07 | Note de cadrage de 2 pages (fin J1) | brief §5 `Note-cadrage`, §11 (2 pages, fin J1) | PARTIEL | 3/3 OK | oui : pertinence du cadrage |
| REQ-08 | Planning 35 h | brief §2 (5 jours, 35 h), §5 `Planning-35h.md` | SATISFAIT ET CONTRÔLÉ | 3/3 OK | non |
| REQ-09 | Rôles et communication | brief §2 (équipe de 2 ou 3), §5 `Roles-et-communication.md` | SATISFAIT ET CONTRÔLÉ | 2/2 OK | oui : titulaires et rôles à fournir par l'équipe |
| REQ-10 | Analyse des IoC, alertes, binaires | brief §5 `04-Analyse`, §8 (analyse des IoC, alertes, binaires) | SATISFAIT ET CONTRÔLÉ | 7/7 OK | oui : jugement analytique des 12 alertes |
| REQ-11 | Chronologie | brief §8 (chronologie à 7 colonnes), §5 `Chronologie.csv` | SATISFAIT ET CONTRÔLÉ | 7/7 OK | oui : interprétation des contradictions |
| REQ-12 | Enrichissement par sources ouvertes tracé | brief §2 (« enrichir depuis des sources ouvertes ») | SATISFAIT ET CONTRÔLÉ | 2/2 OK | non |
| REQ-13 | Événement MISP dédié ingéré | brief §2 et §7 (MISP obligatoire, événement dédié) | SATISFAIT ET CONTRÔLÉ | 1/1 OK | non |
| REQ-14 | Vérification MISP en lecture | brief §7 (relecture par API, comparaison au manifeste), §5 `Verification-MISP.md` | SATISFAIT ET CONTRÔLÉ | voir preuve | non |
| REQ-15 | Bundle STIX 2.1 d'au moins 25 objets liés | brief §2 et §9 (« au moins 25 objets liés ») | SATISFAIT ET CONTRÔLÉ | 9/9 OK | oui : arbitrage du mode de comptage (Q14) |
| REQ-16 | Validation STIX (syntaxe et métier) | brief §9 (validateur STIX 2.1, sortie archivée, contrôle de cohérence métier) | SATISFAIT ET CONTRÔLÉ | voir preuve | non |
| REQ-17 | Matrice ATT&CK vérifiée sur source officielle | brief §2 et §8 (identifiant et nom vérifiés dans une source officielle) | SATISFAIT ET CONTRÔLÉ | 6/6 OK | non |
| REQ-18 | Diamond Model | brief §2 et §8 (Diamond Model) | SATISFAIT ET CONTRÔLÉ | 4/4 OK | oui : jugement sur les inconnues du losange |
| REQ-19 | Attribution et Admiralty | brief §2 et §8 (attribution argumentée, Admiralty A-F et 1-6 séparés) | SATISFAIT ET CONTRÔLÉ | 6/6 OK | oui : jugement d'attribution et cotes Admiralty |
| REQ-20 | Matrice CID | brief §2 (impact sur les actifs), §12 (matrice CID) | SATISFAIT ET CONTRÔLÉ | 3/3 OK | oui : criticités |
| REQ-21 | Cartographie SI par méthode d'analyse de risques | brief §12 (cartographie SI) ; compétence 4 | SATISFAIT ET CONTRÔLÉ | 2/2 OK | oui : méthode d'analyse de risques |
| REQ-22 | Au moins 10 règles Sigma fondées sur l'analyse | brief §10 (au moins 10 règles Sigma fondées sur l'analyse) | SATISFAIT ET CONTRÔLÉ | voir preuve | oui : pertinence opérationnelle avant déploiement réel |
| REQ-23 | Plan de tests et résultats | brief §10 (tests positifs et négatifs, plan et résultats), §5 `Plan-tests.md`, `Resultats-tests.csv` | SATISFAIT ET CONTRÔLÉ | voir preuve | non |
| REQ-24 | Graphe CTI depuis le bundle, script de régénération | brief §9 (graphe depuis le bundle final, script de régénération) | SATISFAIT ET CONTRÔLÉ | voir preuve | non |
| REQ-25 | Rapport stratégique PDF 2 à 3 pages | brief §12 (stratégique 2 à 3 pages) | SATISFAIT ET CONTRÔLÉ | 2/2 OK | oui : lisibilité pour la direction |
| REQ-26 | Rapport tactique PDF 8 à 12 pages | brief §12 (tactique 8 à 12 pages) | SATISFAIT ET CONTRÔLÉ | 5/5 OK | oui : lecture technique par un analyste SOC |
| REQ-27 | Note d'attribution | brief §12 (note d'attribution) | SATISFAIT ET CONTRÔLÉ | 2/2 OK | oui : argumentation |
| REQ-28 | Note ANSSI, 1 page | brief §12 (note ANSSI, une page) | SATISFAIT ET CONTRÔLÉ | 4/4 OK | oui : relecture juridique avant tout usage réel |
| REQ-29 | Note de partage TLP, 1 page | brief §12 (note de partage, une page, TLP) | SATISFAIT ET CONTRÔLÉ | 3/3 OK | oui : politique de partage |
| REQ-30 | Journaux J1 à J5 | brief §11 (journaux J1 à J5) | SATISFAIT ET CONTRÔLÉ | 7/7 OK | non |
| REQ-31 | Soutenance : plan, support PDF, questions | brief §12 (soutenance 20 min + 10 min de questions) | SATISFAIT ET CONTRÔLÉ | 7/7 OK | oui : répétition orale |
| REQ-32 | Couverture des 8 compétences | brief §13 (huit compétences) | SATISFAIT ET CONTRÔLÉ | 3/3 OK | oui : jugement d'un formateur |
| REQ-33 | Manifeste des livrables avec hashes | brief §14 (manifeste avec hash) | SATISFAIT ET CONTRÔLÉ | voir preuve | non |
| REQ-34 | Contrôle final de cohérence | brief §14 (cohérence entre inventaire, MISP, STIX, graphe, rapports, règles) | SATISFAIT ET CONTRÔLÉ | voir preuve | non |
| REQ-35 | Pilotage : tableau de bord, décisions et limites, infrastructure | brief §5 `00-Pilotage`, §14 (tableau de bord à jour) | SATISFAIT ET CONTRÔLÉ | 6/6 OK | non |
| REQ-36 | Dépôt Git local cti-helios-energy (exigence du sujet) | sujet initial : dépôt `cti-helios-energy` **obligatoire depuis le départ** (brief §14 ; l'emplacement seul était à proposer) ; confirmé par le commanditaire | NON SATISFAIT | voir preuve | non |

## 3. Demandes supplémentaires OpenCTI (hors dénominateur)

| ID | Demande | Origine | Statut |
|---|---|---|---|
| SUP-01 | Mission consultable dans OpenCTI : Analyses, Événements, Observations | demande du commanditaire en cours de mission (trois rubriques OpenCTI Analyses, Événements, Observations) : **n'est pas dans le brief initial** | SATISFAIT ET CONTRÔLÉ |
| SUP-02 | Investigation OpenCTI consultable (/dashboard/workspaces/investigations) | demande du commanditaire (tour du 2026-10-07) : investigation consultable dans OpenCTI (`/dashboard/workspaces/investigations`) ; **absente du brief initial** | PARTIEL |
| SUP-03 | RFI OpenCTI consultables (/dashboard/cases/rfis) | demande du commanditaire (tour du 2026-10-07) : RFI consultables dans OpenCTI (`/dashboard/cases/rfis`) ; **absente du brief initial** | SATISFAIT ET CONTRÔLÉ |

## 4. Volet optionnel (hors dénominateur)

| ID | Volet | Origine | Statut |
|---|---|---|---|
| OPT-01 | OpenCTI : correspondance MISP/OpenCTI | brief §7 (OpenCTI « si accessible et pertinent », correspondance MISP/OpenCTI à documenter) | PARTIEL |
| OPT-02 | Cortex : analyses locales | brief §7 (Cortex : analyseurs vérifiés et approuvés) | NON APPLICABLE |
| OPT-03 | Wazuh : rejeu isolé puis production (volet optionnel) | brief §10 (« volet Wazuh optionnel ») ; LISEZ-MOI (« volet 16 Go (Wazuh) ») | SATISFAIT ET CONTRÔLÉ |
| OPT-04 | CrowdSec | brief §2 (CrowdSec seulement si une fonction pertinente est démontrée) | NON APPLICABLE |
| OPT-05 | Consultation dark web | brief §3 (dark web : consultation seulement) | SATISFAIT ET CONTRÔLÉ |

## 5. Autres améliorations internes (ni exigences ni optionnel)

Travaux ajoutés par moi, comptés nulle part dans les couvertures : `Version-ATTACK.md` et `Correspondance-ATTACK-v18-v19.csv` ; `Reconciliation-tests.md` ; `Ecarts-bundle-plateformes.md` ; `Classification-et-validite.md` ; `Diagnostic-OpenCTI.md` ; `Insertion-organisation-MISP.md` ; `Options-restes-production.md` ; `Controles-exigences.csv` et son script ; captures `preuves-consultation/` ; corrections du bundle (T8 à T12) ; `Justification-25-objets-lies.md` ; `Controle-live-2026-10-07.md` ; `Audit-final-criteres.md`.

## 6. Contrôle technique et validation du commanditaire : deux choses distinctes

Selon le §14 du brief, une exigence est **SATISFAITE ET CONTRÔLÉE** si le livrable existe, si le contenu attendu est présent, si la preuve est traçable, si le contrôle a été exécuté et si les limites sont écrites. Rien n'y exige l'avis du commanditaire : il est donc suivi **à part** (colonne `relu_par_commanditaire`, « non » partout à ce jour). Un contrôle technique ne remplace pas une relecture : la dernière colonne du tableau 2 dit quand un jugement humain reste utile. Le contrôle technique volontairement **partiel** est REQ-15 (statut PARTIEL), car la définition de « objets liés » n'est pas fournie : 34 objets sont extrémités d'une relation, 24 si l'on ne compte que les objets analytiques et les identités, 20 si l'on ne compte que les objets analytiques (99 si l'on compte aussi les références de conteneurs) : voir `06-STIX-Graphe/Justification-25-objets-lies.md`.
