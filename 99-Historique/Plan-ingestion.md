# Plan d'ingestion (PROPOSITION : rien n'a été écrit)

Date : 2026-10-06. Statut : **EXÉCUTÉ le 2026-10-06 (P1, P2, P3 pour MISP), voir `Journal-ingestion.csv` et `Verification-MISP.md`. P4 OpenCTI : écriture directe (voir `Plan-modelisation-OpenCTI.md`). P5 Cortex : non exécuté. P6 Wazuh : exécuté (conteneur isolé puis production). P7 CrowdSec : non utilisé.** Le détail des données est dans `Manifeste-ingestion.json` (40 attributs, régénérable par `generer-manifeste.py`).

## 1. Cible et opération, plateforme par plateforme

| # | Cible exacte | Opération | Données écrites ou transmises | Prérequis | Statut |
|---|---|---|---|---|---|
| P1 | MISP `https://172.16.208.253` (CT 3012 sur corbeau, d'après la doc) | Créer **un** événement `[CHALLENGE FICTIF] Helios Energy INC-2026-0302`, distribution 0 (organisation seule), non publié, 40 attributs `to_ids=false`, 2 objets `file`/`domain-ip` | valeurs des 40 IoC (fictives), commentaires de source, étiquettes `tlp:amber`, `admiralty-scale:*` | B-02 (compte), B-03 (isolement) | **Non approuvé** |
| P2 | MISP, lecture | Relire l'événement et ses attributs, comparer au manifeste, archiver les identifiants retournés | aucune écriture | P1 | Non commencé |
| P3 | MISP, export | Export STIX 2.1 de l'événement (module d'export de MISP), puis contrôle de ce que l'export conserve | aucune écriture | P1 | Non commencé |
| P4 | OpenCTI `hiboux:8180` | **Aucune écriture directe.** Lecture seule de ce que la synchronisation MISP vers OpenCTI aurait importé, pour documenter la correspondance | aucune écriture | P1 + B-03 | Non commencé, optionnel |
| P5 | Cortex `https://172.16.171.26` | Aucune analyse prévue par défaut. Si approuvé : analyseurs **locaux seulement** (liste à vérifier via l'API) | à définir | B-02 | Non prévu |
| P6 | Wazuh | Pas de rejeu dans la production. Rejeu uniquement sur un agent/périmètre de test désigné | `05_journaux_bruts.log` | B-06 | Non prévu |
| P7 | CrowdSec | Aucune action | n/a | n/a | Non utilisé |

## 2. Risques identifiés avant écriture

1. **Synchronisation automatique vers la production** : d'après la documentation du vault, MISP alimente OpenCTI (30 min) et TheHive (1 h, filtre par étiquette). **La distribution « organisation seulement » et l'état « non publié » ne constituent PAS une isolation garantie** : la documentation ne mentionne aucun filtre du connecteur OpenCTI (publication, distribution, étiquette, organisation du compte lecteur), et un compte de synchronisation de portée large peut voir des événements non publiés. Tant que la configuration réelle des connecteurs n'a pas été lue (lecture seule, secrets masqués, question Q2), l'isolation est **NON PROUVÉE** et P1 reste suspendue. Après P1 éventuelle : relecture d'OpenCTI (MCP lecture) à deux cycles de synchronisation pour constater l'absence d'importation.
2. **Warninglists MISP** : les IP en 198.51.100.0/24 et 203.0.113.0/24 appartiennent à des plages de documentation ; MISP peut les signaler ou les ignorer en corrélation. Constat à consigner, pas à contourner.
3. **Corrélation avec des données réelles** : MISP corrèle par valeur. Les valeurs étant fictives, une corrélation avec un autre événement serait elle-même à examiner (a priori un événement de test existant, comme l'événement n° 4 ou 5 mentionnés dans la doc).
4. **Doublons à la relance** : recherche par valeur avant chaque création ; journalisation de chaque identifiant retourné dans `Journal-ingestion.csv`.
5. **Aucun secret dans les fichiers** : la clé API sera passée par variable d'environnement dans le terminal, jamais écrite dans un rapport.

## 3. Statut analytique des données écrites

- Aucune galaxie d'acteur (FIN7, Carbanak ou autre) n'est ajoutée : l'attribution est une **hypothèse** (voir DEC-004) ; elle ne sera exprimée, si elle l'est, que dans un commentaire d'événement avec son niveau de confiance.
- Techniques ATT&CK : ajoutées seulement après vérification sur la source officielle, comme galaxies `attack-pattern` rattachées à l'événement avec la mention de statut (observée / probable / non démontrée).
- Cotes Admiralty : celles du SOC sont reprises en étiquettes **comme fournies**, avec un commentaire indiquant qu'elles ne sont pas encore évaluées par l'équipe.
- Victime : `comptabilite-07` figure dans « Targeting data », `to_ids=false`.

Modélisation OpenCTI (trois rubriques) : voir `Plan-modelisation-OpenCTI.md`.

## 4. Ce qu'il faut me répondre pour avancer

1. Compte MISP et mode de transmission de la clé (B-02).
2. Option d'isolement (B-03) : (a) instance isolée, (b) distribution organisation seule **conditionnée** au résultat de la lecture des connecteurs (Q2), (c) pas d'ingestion.
3. Accord explicite pour P1 une fois B-02 et B-03 réglés, éventuellement après révision du manifeste.
