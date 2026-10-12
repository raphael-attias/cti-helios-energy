# Contrôles en direct des plateformes, 2026-10-07 (lecture seule)

Tous les contrôles ci-dessous sont en **lecture seule** (aucune écriture, aucun redémarrage, aucun connecteur touché). Accès : Pharos puis Ansible ciblé (`hiboux`, `misp`, `wazuh`), scripts temporaires supprimés après usage (vérifié pour chacun), jeton OpenCTI lu dans le conteneur et jamais affiché. Interfaces : Chrome de l'utilisateur déjà connecté, pages consultées seulement.

## 1. OpenCTI 6.9.21 (hiboux, API locale)

| Contrôle | Constat | Conclusion |
|---|---|---|
| Version et compte | 6.9.21, compte `admin` (capacités KNOWLEDGE et BYPASS) | écriture possible, avec le jeton d'administration (limite B-15 inchangée) |
| Licence | essai de type `trial`, **expirée**, Enterprise Edition désactivée (bannière rouge dans l'interface) | fonctions Enterprise non garanties : voir investigations |
| Rapport de la mission | `3ec91c0f…` présent, TLP:RED, label `challenge:helios-fictif`, 85 objets contenus, créé par l'équipe fictive | conforme au journal d'ingestion |
| Objets étiquetés | 47 (Directory 1, StixFile 7, System 3, Incident 1, Indicator 8, IPv4 10, Note 3, Observed-Data 4, Report 1, Url 5, User-Account 1, X509 3) | identique à `IDs-cibles-retrait.json` |
| Investigations (`/dashboard/workspaces/investigations`) | rubrique **disponible** dans l'interface ; mutation `workspaceAdd` présente ; bouton « Créer enquête » visible ; **une seule enquête existante, `essaie1`, qui n'est pas de la mission** (0 entité) ; aucune enquête de la mission | pas de doublon à craindre ; création **non faite** |
| RFI (`/dashboard/cases/rfis`) | rubrique **disponible** ; mutation `caseRfiAdd` présente ; flux de statuts NEW, APPROVED, DECLINED ; **une seule RFI existante, `TEST-HL`**, qui n'est pas de la mission ; aucun modèle de dossier (`caseTemplates` vide) | création **non faite** |
| Champs de la RFI | assignés, participants, marquage, label, objets liés, priorité P1 à P4, gravité : tous existent sur l'instance ; pas de champ de date d'échéance dans l'entrée de création | aucune échéance ni destinataire n'est inventé |
| Automatisations pouvant réagir à une création | flux `jira` : filtre sur les types Incident et Case-Incident ET un label non utilisé, donc **ne couvre ni les enquêtes ni les RFI** ; connecteurs TheHive, Wazuh Sightings, MISP : import vers OpenCTI, aucun envoi ; `SOC Case Linker` : code ne traite que `Case-Incident` ; déclencheur « unit » : notifications internes pour l'administrateur, aucun notifieur externe ; enrichissement automatique Google DNS (Domain-Name) et IPinfo (IPv4 et IPv6) : ne concernent pas les enquêtes ni les RFI, mais **une RFI qui rattache des observables ne crée pas de nouvel observable** | risque jugé faible ; limites ci-dessous |
| Limites | les **playbooks** (connecteurs `[PLAYBOOK] Nginx IOC` et `[PLAYBOOK] test`) ne sont pas lisibles par l'API (liste vide, licence expirée) : leur définition n'a pas pu être contrôlée | à surveiller à la création ; aucune garantie documentaire |

## 2. MISP 2.5.46 (hôte `misp`, base en lecture seule)

Événement 6 : organisation propriétaire 2 `CHALLENGE-FICTIF`, distribution 0, **non publié**, 46 attributs, 5 objets, 9 étiquettes d'événement (8 galaxies et `tlp:amber`), 1 rapport d'événement, **0 corrélation**. Événements 1 à 5 présents (feeds et recettes), sans aucune écriture de la mission. Organisations : `stormlab` (1) et `CHALLENGE-FICTIF` (2).

## 3. Wazuh 4.14.7 (hôte `wazuh`, manager)

| Contrôle | Constat |
|---|---|
| Fichiers | `helios_decoders.xml` (14 décodeurs, sha256 `bffcf457…6535`) et `helios_rules.xml` (15 règles, sha256 `999190ee…052f`) présents, **identiques** aux copies locales `helios_decoders.xml` et `helios_rules_prod.xml` |
| Alertes | 27 alertes `helios_challenge` dans le fichier d'alertes du 2026-10-06 (27 identifiants distincts), réparties sur les règles 130101 à 130115 (2 par règle, sauf 130102, 130114 et 130115 : 1) |
| Actions automatiques | **0 mention** de `helios` dans `active-responses.log` et `integrations.log` ; `email_notification` = `no` ; aucune alerte de niveau 10 ou plus (seuil TheHive) |
| Démons | **11 en marche sur 15** : arrêtés `wazuh-clusterd` (cluster `disabled`), `wazuh-maild` (courriel `no`), `wazuh-agentlessd`, `wazuh-csyslogd`. **L'énoncé « 15 sur 15 » de la revue du 2026-10-06 était inexact et est corrigé.** Ce contrôle ne prouve pas que ces 4 arrêts étaient déjà l'état avant la mission ; la configuration les justifie |
| Redémarrage | **aucun** pendant ce contrôle |

## 4. Interfaces consultées aujourd'hui

Investigations et RFI : listes ouvertes (une entrée préexistante chacune). Les captures de l'audit du 2026-10-06 restent dans `preuves-consultation/` ; les rubriques MISP et Wazuh n'ont pas été rouvertes aujourd'hui (contrôles par base et fichiers).

## 5. Ce que ces contrôles ne prouvent pas

Effets sur des événements entrants pendant le redémarrage du 2026-10-06 (non mesurés) ; état des playbooks OpenCTI ; absence d'effets de bord futurs d'une montée de version MISP sur l'organisation insérée en SQL ; correspondance MISP/OpenCTI (le connecteur MISP n'est pas repris).
