# AGENTS.md : contexte de reprise, challenge CTI « Helios Energy »

Point d'entrée pour tout agent qui reprend ce dossier sans l'historique de la conversation. Lire dans cet ordre : ce fichier, `11-Validation/Cloture-finale-mission.md`, `00-Pilotage/Tableau-de-bord.md`, `00-Pilotage/Decisions-et-limites-finales.md`. État au 2026-10-07 (clôture). **La mission n'est pas validée à 100 %** : voir §6.

## 1. Mission

Investigation CTI fictive sur l'attaquant de l'incident INC-2026-0302 (victime fictive Helios Energy, opérateur d'importance vitale). Dossier d'artefacts fourni dans `fourniture/` (7 fichiers, lecture seule, jamais modifiés) : 40 IoC, 12 alertes SIEM, 3 fiches de binaires (**aucun échantillon**), mémo SOC, journal brut. Langue : français. Conclusion d'attribution : **cluster non attribué**, aucun acteur nommé.

Livrables couverts : inventaires, analyse, ATT&CK, Diamond, attribution (Admiralty séparée de la confiance), CID, cartographie SI, MISP, bundle STIX 2.1 (152 objets), graphe, 15 règles Sigma, tests Sigma et Wazuh, rapports et notes PDF, journaux J1 à J5, soutenance, couverture des 8 compétences, manifeste.

## 2. Règles de conduite non négociables

- Aucune hallucination : ne jamais présenter comme fait ce qui n'a pas été contrôlé. Vocabulaire : OBSERVÉ, CORROBORÉ, HYPOTHÈSE, INCONNU, NON TESTÉ.
- Aucun binaire, secret, clé ou jeton dans le dossier. Secrets lus à l'exécution dans l'environnement des conteneurs, jamais affichés.
- **Aucune écriture en production, suppression, reprise de connecteur, publication ou envoi à un tiers sans approbation explicite** de l'utilisateur. Aucun blocage CrowdSec, aucune réponse active Wazuh, aucun envoi Jira ou TheHive.
- Pas de relation artificielle ajoutée dans OpenCTI pour remplir un onglet. Ne pas rendre actifs les indicateurs expirés pour l'affichage.
- Écrire sans tirets longs (« — » ni « – »), ton humain. Vérifier avec `grep -P "—|–"` avant de rendre.
- Ne jamais déclarer 100 % sans preuve. Distinguer contrôle technique, relecture de l'utilisateur et validation du commanditaire.

## 3. Accès à l'infrastructure existante (rien à déployer)

- Chemin : `ssh rapatt@pharos` puis `cd ~/ansible && ansible <hôte> -b -m script|shell` (hôtes : `misp`, `hiboux` = OpenCTI, `wazuh`, `cortex`, `thehive`). Copier un script dans `/tmp` de pharos, l'exécuter via `-m script` (shebang obligatoire), **le supprimer ensuite** (fait pour tout ce qui a été utilisé).
- MISP 2.5.46 : `https://172.16.208.253`, certificat auto-signé, empreinte SHA-256 `29:C8:DC:CF:4A:9F:F8:82:B9:EF:DC:17:7B:76:9C:97:45:82:5C:65:04:8D:46:9E:0B:DA:A0:88:B0:A5:38:16`. Base lisible via `docker exec misp-docker-db-1 mysql` (lecture seule).
- OpenCTI 6.9.21 (Communauté, licence d'essai expirée) : `http://172.16.0.4:8180`, GraphQL local sur hiboux (`127.0.0.1:8180/graphql`, jeton lu dans `xtm-opencti-1`).
- Wazuh 4.14.7 : dashboard `https://10.99.99.3`, manager `single-node-wazuh.manager-1` sur l'hôte `wazuh` (VM 127).
- Interfaces : Chrome de l'utilisateur déjà connecté (extension Claude in Chrome). Ne jamais saisir de mot de passe ; demander à l'utilisateur de se connecter.
- Venv Python : `/Users/rapatt/Projet/cti-helios-env/.venv/bin/python` (stix2, stix2-validator avec schémas OASIS liés, pySigma, PyMuPDF). Pandoc et Chrome headless pour les PDF.

## 4. Ce qui a été écrit en production (06/10 sous autorisation générale ; 07/10 sous approbation explicite par opération)

| Plateforme | Objets | Détail |
|---|---|---|
| MISP | organisation 2 `CHALLENGE-FICTIF` (**insérée en SQL direct**), utilisateur 5 `challenge-writer@helios.test` (Publisher), événement 6 | diffusion 0, non publié, tag `tlp:amber`, 46 attributs, 5 objets, 8 galaxies, 1 rapport d'événement ; fichier de clé supprimé de l'hôte |
| OpenCTI | 47 objets étiquetés `challenge:helios-fictif` (id `bf06ad75-560f-400e-82e3-46ffaa771ab5`), 3 organisations **sans étiquette ni marquage**, 6 labels, 11 références externes, 26 relations, 4 détections, rapport `3ec91c0f-915b-4e1d-9cd9-c1c12c79f342`, incident `a2f66075-be6c-42a9-9524-d428833fd4c1`, 2 pièces jointes Markdown (depuis le 2026-10-10) | TLP:RED, indicateurs expirés et révoqués, aucun domaine créé |
| OpenCTI (2026-10-07, **approbation explicite par opération**) | 1 enquête `14c28507-2b09-48b8-9b36-c2dc2470d64a` (56 entités, 30 relations existantes), 5 RFI (RFI-01 à RFI-05, statut NEW, ouvertes) | liens et suivi : `00-Pilotage/Suivi-RFI.md`, `11-Validation/Audit-final-criteres.md` ; retraits : `IDs-cibles-retrait.json` (`creations_2026-10-07`) |
| OpenCTI (2026-10-07, approbation explicite) | marquage de 3 organisations (label et TLP:RED) | `IDs-cibles-retrait.json` |
| MISP (2026-10-10, approbation explicite) | commentaire des 40 attributs d'IoC de l'événement 6 | cote Admiralty de l'équipe ajoutée (`05-Plateformes/misp_cotes_admiralty.py`, `Verification-MISP.md` §6) ; rien d'autre modifié ; clé du Publisher 5 régénérée puis supprimée de l'hôte |
| Wazuh | `helios_decoders.xml` et `helios_rules.xml` (règles 130101 à 130115, niveaux 4 à 7) dans le volume `single-node_wazuh_etc` ; 27 alertes `helios_challenge` | redémarrage de 41 s |

Formulation exacte à reprendre : **production modifiée, sans effet de bord détecté dans le périmètre des contrôles réalisés.** Retours arrière préparés, non exécutés : `00-Pilotage/Options-restes-production.md`, `Insertion-organisation-MISP.md`. Cibles exactes : `05-Plateformes/IDs-cibles-retrait.json` (ne pas supprimer d'autres labels : « trojanized coding challenge », « matomo analytics », etc. sont de la production).

## 5. Pièges connus

- OpenCTI : connecteurs Google DNS (aucune garde TLP, donc aucun observable domaine) et IPinfo (TLP maximal AMBER, objets en RED) ; flux Jira public filtré sur un label non utilisé ; confiance 15 affichée « 5 - Improbable », sightings affichés « VRAI POSITIF » par défaut.
- OpenCTI : le **graphe de connaissance est sur le rapport**, pas sur l'incident ; l'onglet Indicateurs de l'incident liste seulement `indicates`, or les 8 liens sont `related-to` (voir `05-Plateformes/Diagnostic-OpenCTI.md`, correction C1 à approuver).
- Connecteur `misp-connector-misp-1` : conteneur en marche mais plus d'accès à MISP depuis le 2026-09-23 ; **non repris, non filtré** ; son compte (id 4, organisation 1, lecture seule) ne voit pas l'événement 6. Ne pas le reprendre sans filtre d'exclusion (`import_owner_orgs_not`, nom exact non confirmé).
- MISP : rôle Publisher limité (pas de tag personnalisé, `tlp:red` n'existe pas, pas d'édition d'attributs d'objets) ; hostname sans point refusé ; export STIX en erreur avec galaxies (`excludeGalaxy`) ; attributs d'objets sans `first_seen` donc export daté de l'ingestion (corrigé en T12 dans le bundle local).
- Wazuh : un événement ne produit qu'une alerte (ombrage) ; seuils TheHive niveau 10, courriel 12 ; règles non validées sur de vrais journaux.
- ATT&CK : v19 publiée le **28 avril 2026** ; v18.1 en vigueur en mars 2026 ; **T1070.001 (v18.1) = T1685.005 (v19)** ; tactiques « Defense Evasion » scindées en `stealth` et `defense-impairment` en v19. Méthode retenue : v19.2 avec correspondance v18.1 (`04-Analyse/Version-ATTACK.md`, vérifié contre les bundles officiels `mitre-attack/attack-stix-data`).
- Les heures affichées par les interfaces sont locales (UTC+2). Heures de création exactes OpenCTI : `created_at` de l'API.

## 6. État final des exigences (36 officielles, lecture du brief du commanditaire)

**33 SATISFAITES ET CONTRÔLÉES (33 / 36, 91,7 %), 1 PARTIELLE, 2 NON SATISFAITES.** Aucune n'est relue ni validée par le commanditaire. Détail et preuves : `11-Validation/Audit-final-criteres.md` ; clôture : `11-Validation/Cloture-finale-mission.md` ; relecture critique par l'auteur : `11-Validation/Relecture-finale.md`.

| Exigence | Statut | Raison |
|---|---|---|
| REQ-04 analyse des binaires | NON SATISFAIT | échantillons non fournis (le LISEZ-MOI le dit) ; RFI-01 ouverte |
| REQ-36 dépôt Git `cti-helios-energy` | NON SATISFAIT | dépôt absent : l'utilisateur le créera lui-même à la fin, quand tout sera fini et validé (ne rien créer ; 3 demandes d'approbation sans suite le 2026-10-07) ; procédure prête (`11-Validation/preparer-depot-git.sh`) ; ne rien créer sans accord |
| REQ-07 note de cadrage | PARTIEL | produite après l'échéance « fin J1 » |
| REQ-15 bundle ≥ 25 objets liés | satisfait sous la méthode conservatrice de l'équipe | 27 objets de renseignement liés (25 sans 2 ajouts) ; définition non confirmée (RFI-05) ; `06-STIX-Graphe/Justification-25-objets-lies.md` |

Hors dénominateur : volet Wazuh (satisfait), consultation dark web indirecte par sources en clair (satisfaite, `03-Sources/Darkweb-consultatif.md` : aucun accès .onion, aucune interaction), correspondance MISP/OpenCTI (partielle), consultation OpenCTI et 5 RFI (satisfaites), enquête OpenCTI (partielle : lisibilité limitée), Cortex et CrowdSec (non applicables, justifiés). **TheHive et Cortex n'ont pas été utilisés** (`05-Plateformes/Verification-TheHive.md`, `Verification-Cortex.md`).

## 7. Décisions, arbitrages non obtenus et opérations non faites

Tout est dans `00-Pilotage/Decisions-et-limites-finales.md`. À retenir : le dépôt Git n'est pas créé (non approuvé) ; les 2 PDF joints au rapport OpenCTI ont été remplacés le 2026-10-10 par `Rapport-strategique.md` et `Rapport-tactique.md` (demande de l'utilisateur : plutôt du Markdown que du PDF ; archives dans `99-Historique/pieces-jointes-opencti-avant-remplacement/`) ; les retraits, le filtre du connecteur MISP, `indicates`, `tlp:red` et `valid_from` n'ont pas été demandés (procédures préparées dans `00-Pilotage/Options-restes-production.md`). Ne rien exécuter de cela sans demande explicite.

## 8. Carte du dossier

| Dossier | Nature | Contenu |
|---|---|---|
| `fourniture/` | **sources originales** (lecture seule) | 7 fichiers d'origine, jamais modifiés |
| `01-Cadrage/` à `04-Analyse/` | **livrables finaux** | note de cadrage, inventaires, sources, analyses, ATT&CK, Diamond, attribution, CID, cartographie |
| `05-Plateformes/` | livrables, preuves et scripts | `Methodes-integration-et-import.md`, vérifications MISP, OpenCTI, TheHive, Cortex, guide de consultation, journaux et scripts d'ingestion |
| `06-STIX-Graphe/`, `07-Detection-Tests/` | livrables et preuves | bundle, graphe, comptage des objets liés, 15 règles Sigma, tests Wazuh, réconciliation |
| `08-Rapports/`, `09-Journal-mission/`, `10-Soutenance/` | **livrables finaux** | rapports et notes (PDF), journaux J1 à J5, soutenance (support et préparation aux questions) |
| `00-Pilotage/` | pilotage final | tableau de bord, matrice, `Decisions-et-limites-finales.md`, `Suivi-RFI.md`, restes en production |
| `11-Validation/` | **clôture, preuves, scripts de contrôle** | `Cloture-finale-mission.md`, `Audit-final-criteres.md`, contrôles, manifeste, captures, scripts de régénération |
| `99-Historique/` | **historique, non final** | registres de questions et de blocages, plans d'exécution, revue du 2026-10-06, anciennes versions de la matrice |

## 9. Commandes utiles

- Tout régénérer dans l'ordre (local, aucune écriture en production) : `bash 11-Validation/regenerer-tout.sh`. Enchaîne la chaîne STIX, les tests Sigma, la matrice, le tableau de bord, la revue, les PDF modifiés, `controle-coherence.py` (42 contrôles), `controles-exigences.py` (89 contrôles, 2 KO attendus sur REQ-15), le manifeste et `verifier-manifest.py`.
- Chronologie de présentation : `python3 04-Analyse/generer-timeline.py` (génère `04-Analyse/Timeline-incident.md` et le bloc balisé `TIMELINE` en tête de `10-Soutenance/Resume-prez-doc.md` depuis `Chronologie.csv`, `Matrice-analyse-alertes.csv` et `Matrice-ATTACK.csv` ; ne pas éditer le bloc à la main).
- Chaîne STIX seule : `bash 11-Validation/regenerer-stix.sh` (bundle, validation 0 erreur et 218 avertissements classés, graphe, inventaire, `Derives-du-bundle.txt`).
- Les statuts ne se modifient pas à la main : éditer `11-Validation/maj-matrice.py`, puis relancer `regenerer-tout.sh`. `Tableau-de-bord.md`, `Exigences-origine.md`, `Suivi-RFI.md` et `Audit-final-criteres.md` sont générés ; `Cloture-finale-mission.md` est rédigé à la main à partir de leurs chiffres.
- Le rendu PDF n'est pas déterministe (dates en métadonnées) : ne régénérer que les PDF dont le Markdown a changé.

## 10. Corrections du bundle STIX (locales uniquement)

T8 identifiants des observables en UUIDv5, T9 relation `downloaded-from` entre `observed-data` reportée sur les SCO, T10 `valid_from` par indicateur (première alerte), T11 `based-on` vers `observed-data`, T12 `first_observed` des 5 objets MISP datés de l'ingestion, T14 (2026-10-10) source et date de collecte sur chaque objet (`x_helios_*` sur les 39 observables). Les plateformes ne contiennent pas ces corrections (voir `Ecarts-bundle-plateformes.md`).

## 11. Limites irréductibles

Aucun échantillon binaire ; une seule ligne de balise ; journal Security effacé ; aucune source indépendante pour l'attribution ; SIIV, secteur, équipe et temps réels inconnus (le statut OIV est fourni par l'énoncé) ; sujet officiel et glossaire TLP absents ; aucun taux de faux positifs de production mesuré ; jeux de test synthétiques écrits par l'équipe ; NIS 2 vérifié seulement par des sources secondaires ; aucune relecture par un tiers.
