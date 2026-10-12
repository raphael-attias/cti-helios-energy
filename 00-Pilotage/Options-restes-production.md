# Restes en production : état conservé et procédures de retrait préparées

Mise à jour : 2026-10-07. **État conservé à la clôture : l'option A (maintien) est appliquée de fait, parce qu'aucun retrait n'a été demandé.** Rien n'est retiré, aucun connecteur n'est repris ni modifié. Les options B, C et D sont des **procédures préparées et non exécutées** : elles ne sont exécutables que sur demande explicite du commanditaire (arbitrage Q26 et Q28 non obtenu, voir `Decisions-et-limites-finales.md`). Chaque procédure est indépendante des autres, sauf dépendance indiquée. Les cibles exactes (identifiants) sont dans `05-Plateformes/IDs-cibles-retrait.json`.

## Option A : maintien des objets pédagogiques (état actuel)

| Point | Contenu |
|---|---|
| Cibles | tout ce qui est listé dans l'option B, C et D : événement MISP 6, 55 objets OpenCTI étiquetés (47 d'origine, 3 organisations, 5 RFI) plus l'enquête, 2 fichiers Wazuh, 27 alertes |
| Intérêt | la soutenance et le contrôle du commanditaire peuvent se faire sur les plateformes réelles ; aucun risque d'erreur de suppression |
| Impacts pendant le maintien | MISP : aucun (diffusion 0, invisible hors organisation 2 et administrateurs) ; OpenCTI : 47 objets visibles par tous les comptes habilités RED (l'administrateur y voit tout) ; **Wazuh : les règles 130101 à 130115 restent actives sur de vrais événements** (voir B) |
| Dépendances | aucune ; le connecteur MISP reste dans son état actuel |
| Date de fin du maintien | non fournie : le maintien dure tant qu'aucun retrait n'est demandé (limite définitive) |
| Retour arrière | sans objet |

## Option B : retirer les règles et décodeurs Wazuh

| Point | Contenu |
|---|---|
| Cibles exactes | conteneur `single-node-wazuh.manager-1` (VM 127, hôte `wazuh`) ; fichiers `/var/ossec/etc/decoders/helios_decoders.xml` (sha256 `bffcf457…6535`, 14 décodeurs) et `/var/ossec/etc/rules/helios_rules.xml` (sha256 `999190ee…2052f`, 15 règles, identique à `07-Detection-Tests/wazuh/helios_rules_prod.xml`) ; tous deux dans le volume `single-node_wazuh_etc` (ils survivent à une recréation du conteneur) |
| Actions | supprimer ces 2 fichiers puis `wazuh-control restart` du manager |
| Impacts | **redémarrage du manager (≈ 41 s mesurés au déploiement)** pendant lequel l'analyse est interrompue ; les 27 alertes déjà indexées (`wazuh-alerts-4.x-2026.10.06`, `rule.groups: helios_challenge`) restent consultables (leur purge relève de la politique de rétention des index) ; plus de décodage « helios-* » |
| Pourquoi y penser | ces règles ne sont pas validées sur de vrais journaux Windows : elles peuvent produire des alertes de niveau 4 à 7 sur des événements réels qui ressemblent aux nôtres (Office lançant PowerShell, tâche planifiée, etc.). Elles restent sous le seuil 10 de l'intégration TheHive et sous le seuil 12 du courriel, et aucune réponse active n'y est rattachée : **pas de déclenchement automatique d'action** |
| Dépendances | aucune avec MISP ou OpenCTI ; il faut que personne ne soit en train d'analyser une alerte `helios_challenge` |
| Retour arrière | redéposer les 2 fichiers (copies dans `07-Detection-Tests/wazuh/`) puis redémarrer |
| Vérification après coup | `wazuh-analysisd -t` sans erreur ; absence des deux fichiers ; `wazuh-control status` : démons en marche ; test `POST /events` avec une ligne de journal du dossier : plus d'alerte `helios_challenge` |

## Option C : retirer les objets MISP et OpenCTI

Ordre recommandé : OpenCTI d'abord (rien n'en dépend), MISP ensuite.

### C1. OpenCTI (suppression, trace conservée dans `Journal-ingestion.csv`)

| Point | Contenu |
|---|---|
| Cibles exactes | les **47 objets d'origine** de l'étiquette `challenge:helios-fictif` (id `bf06ad75-560f-400e-82e3-46ffaa771ab5`), auxquels s'ajoutent depuis le 2026-10-07 les 3 organisations de support, les 5 RFI (même étiquette) et l'enquête (par identifiant, voir `IDs-cibles-retrait.json`) : 1 rapport, 1 incident, 3 notes, 8 indicateurs, 4 données observées, 27 observables (10 IPv4, 7 fichiers, 5 URL, 3 certificats, 1 compte, 1 dossier), 3 systèmes ; les **20 relations étiquetées** et **4 détections** ; les **6 relations `based-on`** non étiquetées (elles tombent avec leurs extrémités) ; les **3 organisations** sans étiquette (ids dans le fichier de cibles) ; les **6 labels** de la mission ; les **11 références externes** dont `source_name` commence par « Dossier Helios » ; les 2 PDF joints au rapport |
| À ne PAS supprimer | tout autre label (par exemple « trojanized coding challenge », « matomo analytics », « google analytics »), les techniques ATT&CK (entités AlienVault et T1685.005 MITRE) liées par `uses`, les connecteurs, les 435 détections Wazuh de production |
| Impacts | les 8 relations `uses` vers les techniques disparaissent (les techniques restent) ; plus rien pour le contrôle du commanditaire ; les entités ATT&CK partagées ne sont pas touchées |
| Dépendances | **ne pas supprimer par recherche de nom** : utiliser les identifiants du fichier de cibles ; **avant** : exporter le contenu (sauvegarde STIX du rapport) si on veut garder une trace ; la suppression met les objets à la corbeille d'OpenCTI (rétention) avant purge |
| Retour arrière | restauration depuis la corbeille tant qu'elle n'est pas purgée ; sinon réingestion avec `octi_ingest.py` à partir des manifestes locaux (`Manifeste-OpenCTI.json`) |
| Vérification | l'étiquette `challenge:helios-fictif` ne filtre plus aucun objet ; comptages Rapports, Incidents, Détections et Observables revenus à leur valeur initiale (435 détections, 0 incident, 0 donnée observée) |

### C2. MISP (suppression, après sauvegarde de la base)

| Point | Contenu |
|---|---|
| Cibles exactes | événement 6 (uuid `33c1053e-e1e1-405f-ae75-b1c747a7f7b2`) avec ses 46 attributs, 5 objets, 8 galaxies, 1 rapport d'événement ; utilisateur 5 `challenge-writer@helios.test` et sa clé d'API ; organisation 2 `CHALLENGE-FICTIF` |
| Impacts | aucun sur les événements 1 à 5 de l'organisation 1 ; l'export STIX et `Export-MISP-brut.json` du dossier restent les seules traces |
| Dépendances | supprimer l'événement et l'utilisateur **avant** l'organisation (MISP refuse sinon) ; ne pas passer par le SQL |
| Retour arrière | sauvegarde de la base MISP faite avant (étape 1 de `Insertion-organisation-MISP.md`, prérequise et non faite) ; sinon réingestion par `misp_challenge.py` |
| Vérification | `cake organisation list` : organisation 1 seule ; événement 6 absent ; connecteur OpenCTI : aucun changement |

## Option D : filtrer avant toute reprise du connecteur MISP vers OpenCTI

| Point | Contenu |
|---|---|
| Cible exacte | conteneur `misp-connector-misp-1` (image `opencti/connector-misp:6.9.21`, sur hiboux) ; **conteneur en fonctionnement** (démarré le 2026-09-23 18:15) mais **aucun accès à MISP relevé depuis le 2026-09-23** avant mon test de lecture du jour ; interrogation toutes les 30 minutes configurée (`PT30M`), import depuis le 2026-09-12 |
| Ce que fait le connecteur aujourd'hui | aucun filtre : il importe tout événement visible par son compte MISP |
| Compte utilisé (vérifié en lecture le 2026-10-06) | utilisateur id 4, organisation 1 (`stormlab`), rôle **lecture seule**, pas administrateur du site : **ne voit pas l'événement 6** (réponse vide à une recherche sur cet identifiant). Mon test de lecture a lui-même mis à jour la date du dernier accès de ce compte |
| Risque | l'événement 6 devient importable si on change le compte du connecteur (administrateur du site ou organisation 2) ou la diffusion de l'événement |
| Paramètres supportés par le connecteur (trouvés dans son code) | `import_owner_orgs_not`, `import_creator_orgs_not`, `import_owner_orgs`, `import_distribution_levels`, `import_tags`, `import_tags_not`, `import_threat_levels`, `import_only_published` |
| Filtre qui serait posé | exclure l'organisation propriétaire `CHALLENGE-FICTIF` (variable d'environnement correspondant à `import_owner_orgs_not`, nom exact non confirmé, à vérifier dans la documentation du connecteur avant tout usage) **et** n'importer que les niveaux de diffusion voulus ; vérifier qu'il n'existe pas déjà d'autre valeur |
| Impacts | redémarrage du conteneur du connecteur ; **la file de 227 K bundles n'est pas purgée** (hors périmètre : non touchée) ; une reprise ferait ingérer des événements en attente dans OpenCTI de production |
| Dépendances | prérequis **avant** toute reprise, sinon sans objet ; la reprise elle-même relève du commanditaire (Q28, non tranchée) ; peut se faire indépendamment de A, B, C |
| Retour arrière | remettre l'ancienne configuration du connecteur et le redémarrer |
| Aujourd'hui | **rien n'est repris, rien n'est filtré** |

## Récapitulatif : ce qu'exigerait chaque procédure

| Option | Condition d'exécution | Risque principal | Réversible |
|---|---|---|---|
| A maintien (état actuel) | aucune | règles Wazuh actives sur de vrais événements | oui |
| B règles Wazuh | demande explicite (redémarrage) | 41 s sans analyse | oui |
| C1 OpenCTI | demande explicite (suppression) | erreur de cible | partiellement (corbeille) |
| C2 MISP | demande explicite (suppression, sauvegarde préalable) | purge irréversible | par sauvegarde |
| D filtre connecteur | demande explicite (reconfiguration et redémarrage) | reprise involontaire de la file | oui |
