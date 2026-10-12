# Guide de consultation : Helios Energy (MISP, Wazuh, OpenCTI)

Date : 2026-10-07 (clôture). **Statut des contrôles** : comptages **vérifiés par API, puis revus dans les interfaces les 2026-10-06 et 2026-10-07** (session Chrome de l'utilisateur déjà connectée ; captures dans `11-Validation/preuves-consultation/`). Revue du 2026-10-07 dans l'interface : Analyses (1 rapport), Événements (1 incident, 4 données observées, 4 détections, filtrés par étiquette), Observations (27 observables, 8 indicateurs), enquête et RFI. **Réserves** : (1) **le graphe de connaissance se consulte sur le RAPPORT** (`/dashboard/analyses/reports/3ec91c0f-915b-4e1d-9cd9-c1c12c79f342`, onglet Connaissance) : la page de l'incident n'a pas d'écran graphe dans cette version (voir `Diagnostic-OpenCTI.md`) ; (2) l'onglet Indicateurs de l'incident est vide, car les 8 liens sont `related-to` : les indicateurs se lisent dans « Entités liées » (choix maintenu) ; (3) le rapport porte 2 pièces jointes Markdown (onglet Données), `Rapport-strategique.md` et `Rapport-tactique.md`, versions du 2026-10-10 (le graphe de l'annexe n'y est pas inclus : voir `06-STIX-Graphe/Graphe-CTI.pdf`) ; (4) les libellés affichés par la plateforme (« VRAI POSITIF » par défaut des détections, confiance 15 affichée « 5 - Improbable ») sont ceux de l'instance ; (5) licence d'essai expirée (bandeau rouge) : Enterprise désactivée, sans effet sur la consultation.

Base OpenCTI : `http://172.16.0.4:8180` (version 6.9.21). Étiquette de la mission : `challenge:helios-fictif` (id `bf06ad75-560f-400e-82e3-46ffaa771ab5`).

## 1. OpenCTI : Analyses

Menu **Analyses**.

| Élément | Lien (relatif à la base) | Relu par API |
|---|---|---|
| Rapport « [CHALLENGE FICTIF] Helios Energy — Investigation CTI » | `/dashboard/analyses/reports/3ec91c0f-915b-4e1d-9cd9-c1c12c79f342` | type internal-report, TLP:RED, 103 objets contenus, 7 références externes, 2 pièces jointes Markdown |
| Note N-ALERTES (registre des 12 alertes) | `/dashboard/analyses/notes/2dbf2832-9ff1-47a3-880e-d5b3cbe9b682` | présente |
| Note N-LIMITES | `/dashboard/analyses/notes/51515b48-622c-46bb-a33c-653d21a00f99` | présente |
| Note N-ATTRIB | `/dashboard/analyses/notes/c452ee0b-cfaf-4e48-8587-f868019832e1` | présente |
| Filtre rapports (étiquette) | http://172.16.0.4:8180/dashboard/analyses/reports?filters=%7B%22mode%22%3A%22and%22%2C%22filters%22%3A%5B%7B%22key%22%3A%22objectLabel%22%2C%22operator%22%3A%22eq%22%2C%22values%22%3A%5B%22bf06ad75-560f-400e-82e3-46ffaa771ab5%22%5D%2C%22mode%22%3A%22or%22%7D%5D%2C%22filterGroups%22%3A%5B%5D%7D | ouvert dans l'interface le 2026-10-07 : 1 rapport de la mission |

**Comptage Analyses (mission)** : 1 rapport + 3 notes = **4**. Hors comptage : 11 références externes (7 fichiers du dossier, 4 lignes de journal), documentaires.

## 2. OpenCTI : Événements

Menu **Événements** : Incidents, Détections (sightings), Données observées.

| Élément | Lien | Relu par API |
|---|---|---|
| Incident « [CHALLENGE FICTIF] Helios Energy — Intrusion » | `/dashboard/events/incidents/a2f66075-be6c-42a9-9524-d428833fd4c1` | first_seen 2026-03-02T08:31Z, last_seen 2026-03-07T09:02Z (**bornes d'observation**), TLP:RED, 27 relations (8 `related-to`, 15 `uses`, 4 `targets`) |
| Données observées (4) | filtre : http://172.16.0.4:8180/dashboard/events/observed_data?filters=%7B%22mode%22%3A%22and%22%2C%22filters%22%3A%5B%7B%22key%22%3A%22objectLabel%22%2C%22operator%22%3A%22eq%22%2C%22values%22%3A%5B%22bf06ad75-560f-400e-82e3-46ffaa771ab5%22%5D%2C%22mode%22%3A%22or%22%7D%5D%2C%22filterGroups%22%3A%5B%5D%7D | 4 objets, 1 occurrence chacun |
| Détections (4) | filtre : http://172.16.0.4:8180/dashboard/events/sightings?filters=%7B%22mode%22%3A%22and%22%2C%22filters%22%3A%5B%7B%22key%22%3A%22objectLabel%22%2C%22operator%22%3A%22eq%22%2C%22values%22%3A%5B%22bf06ad75-560f-400e-82e3-46ffaa771ab5%22%5D%2C%22mode%22%3A%22or%22%7D%5D%2C%22filterGroups%22%3A%5B%5D%7D | 4 sightings (indicateurs IND-04, 06, 07, 08 vers comptabilite-07, dc-01, srv-fichiers-02) |

**Comptage Événements (mission)** : 1 + 4 + 4 = **9**. Avant la mission : Incidents 0, Données observées 0, Détections 435 (production, entité « Wazuh ») : **les détections de la mission ne sont pas des résultats du rejeu Wazuh** ; elles sont dérivées des alertes fournies. Pour les exclure des 435 : auteur « [CHALLENGE FICTIF] Dossier pédagogique (SOC Helios) » ou étiquette de la mission.

## 3. OpenCTI : Observations

Menu **Observations** : Observables, Indicateurs, Artefacts.

| Élément | Filtre | Comptage relu |
|---|---|---|
| Observables | http://172.16.0.4:8180/dashboard/observations/observables?filters=%7B%22mode%22%3A%22and%22%2C%22filters%22%3A%5B%7B%22key%22%3A%22objectLabel%22%2C%22operator%22%3A%22eq%22%2C%22values%22%3A%5B%22bf06ad75-560f-400e-82e3-46ffaa771ab5%22%5D%2C%22mode%22%3A%22or%22%7D%5D%2C%22filterGroups%22%3A%5B%5D%7D | **27** : IPv4 10, URL 5, Fichier 7, Certificat X509 3, Compte utilisateur 1, Dossier 1 |
| Indicateurs | http://172.16.0.4:8180/dashboard/observations/indicators?filters=%7B%22mode%22%3A%22and%22%2C%22filters%22%3A%5B%7B%22key%22%3A%22objectLabel%22%2C%22operator%22%3A%22eq%22%2C%22values%22%3A%5B%22bf06ad75-560f-400e-82e3-46ffaa771ab5%22%5D%2C%22mode%22%3A%22or%22%7D%5D%2C%22filterGroups%22%3A%5B%5D%7D | **8** (expirés par choix, score 20, non destinés à la détection) |
| Artefacts | n/a | **0** (aucun contenu binaire) |

**Comptage Observations (mission)** : 27 + 8 = **35**, plus depuis le 2026-10-07 **4 infrastructures** (menu Observations, Infrastructures) et **1 outil créé** (`powershell.exe`, menu Arsenal, Outils) ; `schtasks` et `Wevtutil` sont des outils MITRE de production reliés à l'incident sans être modifiés. Aucun observable de type nom de domaine n'est créé (connecteur Google DNS automatique sans garde TLP). Le graphe de connaissance de l'incident (onglet « Connaissances ») relie incident, systèmes, techniques (8 relations `uses`), indicateurs (`related-to`, `based-on`) et détections ; vérifié par API (20 relations étiquetées + 6 `based-on` + 4 détections + 11 relations ajoutées le 2026-10-07 pour l'infrastructure et les outils) ; **dans l'interface, la liste « Tout » de l'incident montre 20 entités (techniques, systèmes, organisation), « Entités liées » les 8 indicateurs, et le graphe du rapport (onglet Connaissance du rapport) s'affiche avec incident, techniques, systèmes, indicateurs et observables**.

Autres : Entités, Systèmes (3), Organisations (3 fictives).

## 4. MISP

Instance `https://172.16.208.253` (certificat auto-signé ; identité du serveur vérifiée par empreinte, voir `99-Historique/Revue-cloture.md`). Événement **id 6**, uuid `33c1053e-e1e1-405f-ae75-b1c747a7f7b2`, lien `/events/view/6` (visible de l'organisation CHALLENGE-FICTIF et des administrateurs du site, pas des autres organisations). 46 attributs, 5 objets, 8 galaxies ATT&CK, 0 corrélation. Filtre : événements dont l'info commence par « [CHALLENGE FICTIF] ». Détail : `Verification-MISP.md`.

## 5. Wazuh

Dashboard de l'infrastructure existante. **Source de test** : API (`location: API-Webhook`), agent `wazuh.manager`. **Filtre** : `rule.groups: helios_challenge` ; **identifiants de règles** 130101 à 130115 ; **vue de données** : index `wazuh-alerts-*` (index du jour `wazuh-alerts-4.x-2026.10.06`) ; **période** 2026-10-06 de 10:26 à 10:28 UTC ; **27 alertes** (relues dans l'indexeur par API) ; événements d'exemple : « 2026-03-02T08:31:00Z comptabilite-07 Sysmon: Process Create: winword.exe -> powershell.exe… » (règle 130101), « 2026-03-05T15:31:00Z dc-01 Zeek: large outbound 203.0.113.28:8080 bytes=2469135790 cleartext » (130112). Distinction : **alertes du dossier** (12 lignes d'origine fournies) ; **événements rejoués** (les mêmes 12 lignes + 15 synthétiques positifs + 18 négatifs, `Resultats-wazuh.csv`) ; **alertes réellement générées par Wazuh** (27). Les alertes de test portent l'heure du traitement, pas celle de la ligne (conservée dans `full_log`). Affichage dans le dashboard : **contrôlé le 2026-10-06** (Discover, vue de données `wazuh-alerts-*`, requête `rule.groups: helios_challenge`, période 10:20 à 10:35 UTC, **27 hits**, `rule.id` présent sur 27/27).

## 6. OpenCTI : enquête et RFI (créées le 2026-10-07 après approbation)

| Élément | Lien (relatif à la base) | Relu |
|---|---|---|
| Enquête « [CHALLENGE FICTIF] Helios Energy — Investigation CTI » | `/dashboard/workspaces/investigations/14c28507-2b09-48b8-9b36-c2dc2470d64a` | 56 entités et 30 relations existantes, aucun acteur ; API et interface ; capture `opencti-investigation-graphe-vue-arbre.jpg` (vue en arbre, la plus lisible ; libellés qui se chevauchent, aucune mise en page enregistrée) |
| Liste des RFI | `/dashboard/cases/rfis` | 5 RFI de la mission, statut NEW ; capture `opencti-rfi-liste-5-rfi-ouvertes.jpg` |
| RFI-01 à RFI-05 | `/dashboard/cases/rfis/<identifiant>` : identifiants dans `00-Pilotage/Suivi-RFI.md` | ouvertes, sans réponse, TLP:RED, sans assigné ni échéance |

Les RFI sont des demandes sans réponse : l'information manquante est une limite finale (`00-Pilotage/Decisions-et-limites-finales.md`).
