# Vérification OpenCTI (lecture seule)

Date : 2026-10-06. Aucune donnée créée, modifiée ni supprimée. Chaque constat porte sa **méthode** : **UI** = interface web consultée dans le Chrome de l'utilisateur déjà connecté (extension Claude in Chrome) ; **MCP** = serveur MCP `opencti` de la session (API en lecture) ; **DOC** = documentation du vault SOC-Homelab, non revérifiée.

Transparence : la session de l'interface est celle du compte **admin** de l'utilisateur. Actions réalisées : navigation, une recherche « Helios », une recherche en masse, le retrait d'un chip de filtre de vue sur la page Incidents (aucune donnée touchée), l'ouverture puis la fermeture sans validation du panneau « Créer un observable ». Aucun formulaire soumis.

## 1. Version, édition, licence

| Constat | Valeur | Méthode |
|---|---|---|
| Version de la plateforme | **6.9.21** | UI (Paramètres) ; cohérent avec DOC |
| Édition | **Communauté**, mode autonome, 1 nœud | UI |
| Licence Enterprise | **Essai expiré** (début 2026-03-09, fin 2026-04-09) ; bandeau rouge « Enterprise Edition is disabled » | UI |
| Moteur de recherche, bus, cache | Elasticsearch 8.19.9, RabbitMQ 4.2.4, Redis 8.4.0 | UI |
| Conséquence | Fonctions EE indisponibles (AI Powered désactivé, restrictions d'accès fines, partage par organisation et playbooks non utilisables ; non testés individuellement) | UI (état) / déduction |

## 2. Rubriques visibles (menu latéral)

| Rubrique | Entrées vues | Méthode |
|---|---|---|
| **Analyses** | Rapports, Groupements, Analyses de code malveillant, Couvertures de sécurité, Notes, Références externes | UI |
| Cases | Réponses aux incidents, Demandes d'informations, Demandes de retrait, Tâches, Commentaires | UI |
| **Événements** | **Incidents, Détections (= Sightings), Données observées** | UI |
| **Observations** | Observables, Artefacts, Indicateurs (liste lue partiellement : d'autres entrées éventuelles non relevées) | UI |
| Autres | Menaces, Arsenal, Techniques, Entités, Localisations, Tableaux de bord, Enquêtes, PIR | UI |

Les trois rubriques demandées (Analyses, Événements, Observations) **existent** dans l'interface. Cela ne dit rien encore sur l'affichage de la mission, aucun objet n'étant créé.

## 3. Droits

| Constat | Méthode |
|---|---|
| Compte de l'interface : `admin`, « Principal admin account », courriel rapatt@littlestorm.eu, aucune organisation | UI (Profil) |
| Boutons « Créer rapport », « Créer incident », « Créer donnée observée », « Créer observable » visibles | UI |
| Accès aux pages Paramètres, moteur de règles, connecteurs, partage | UI |
| **Droits d'écriture réels : NON TESTÉS** (aucune écriture) ; droits du jeton utilisé par le MCP : INCONNUS (lectures réussies seulement) | n/a |
| Recommandation : l'écriture ne devrait pas se faire avec le compte administrateur principal mais avec un compte dédié aux droits limités | décision prise : jeton d'administration (Q22) |

## 4. Types d'objets réellement accessibles

**Observables** (liste du panneau de création) : Adresse email, IPv4, IPv6, MAC, Artefact, Carte de paiement, Certificat X509, Clé cryptographique, Clé de registre Windows, Valeur de clé de registre Windows, Clé SSH, Compte bancaire, Compte utilisateur, Contenu média, Dossier, Fichier, Informations d'identification, Logiciel, Mail, Partie MIME, Mutex, Nom d'hôte, Nom de domaine, Numéro de suivi, Numéro de téléphone, Persona, Processus, Système autonome, Texte, Trafic réseau, URL, User agent, Wallet de cryptomonnaie. Types d'entité cachés : aucun (champ vide dans les paramètres). Méthode : UI.

Création possible (boutons vus) pour Rapport, Incident, Donnée observée. **Indicateur, Note, Détection (Sighting), Identité, Label** : types connus du modèle, boutons de création **non consultés**. Les paires de relations autorisées (par exemple Incident → uses → Attack-Pattern) : **non vérifiées** ; elles doivent l'être avant écriture.

## 5. Contenu actuel de la plateforme (comptages vus)

| Élément | Comptage | Méthode |
|---|---|---|
| Rapports | ≈ 1,95 K (auteur dominant AlienVault ; marquage TLP:CLEAR) | UI |
| Incidents | **0** (même après retrait du filtre de vue) | UI |
| Détections (Sightings) | **435** (page affichant « 1 - 25 / 435 » ; filtre de vue à valeur vide non réévalué) ; entité observée « Wazuh » | UI |
| Données observées | **0** | UI |
| Observables | ≈ 352 K (types vus : Fichier, URL, Nom d'hôte, IPv4 ; auteurs stormlab, Stormsecurity, AlienVault) | UI |
| Indicateurs | ≈ 118,69 K (597 en 24 h) | UI (tableau de bord) |
| Documents au total | 105,1 M | UI (surveillance) |
| Mission « Helios Energy » existante | **Aucune** : la recherche « Helios » ne trouve que `heliosup.info` (indicateur et domaine) et `helios.dns-parking.com`, sans rapport avec la mission | UI |
| Collision des valeurs IoC avec l'existant | **0 entité connue** sur 38 valeurs saisies en recherche en masse. Limites : une valeur (certificat de IOC-035) a été **mal saisie par moi** ; IOC-038 et IOC-039 n'ont pas été saisies ; donc 37 valeurs valablement testées sur 40. | UI |

## 6. Mécanismes qui touchent la production (relevés)

| Élément | État | Risque pour la mission |
|---|---|---|
| Moteur de règles d'inférence | Activé, 0 entité déduite, 0 relation inférée ; toutes les règles listées sont **désactivées** | Faible aujourd'hui ; ne pas activer |
| Connecteurs d'enrichissement **automatiques** | **Google DNS**, **IPinfo** (démarré), FIRST EPSS ; ImportDocument automatique | La création d'un observable domaine ou IPv4 peut **transmettre la valeur à un service tiers** (Google DNS, IPinfo). Portée et TLP maximal des connecteurs : **non lus** |
| Cortex | Manuel | Pas de déclenchement automatique |
| Connecteur MISP | Actif ; **227,32 K bundles en attente** ; 1 seul worker ; débit observé 2,6 bundles/s | Les écritures par bundle passent après cette file ; MISP vers OpenCTI reste actif |
| Connecteurs TheHive, SOC Case Linker, Wazuh Sightings, CrowdSec Import | Actifs | `Wazuh Sightings` crée des sightings de production à partir de l'indexeur Wazuh : à ne jamais alimenter par un rejeu |
| Flux live `jira` | **Public : OUI**, démarré, 1 consommateur sain ; connecteur « Atlassian JIRA » actif | Les événements créés (incident, rapport) peuvent alimenter Jira selon des **filtres non lus** |
| Collections TAXII | Aucune | n/a |
| Flux CSV | Page vide à la consultation : **non contrôlé** | À vérifier |
| Gestionnaire de rétention, déclin des indicateurs, corbeille | Activés | Les indicateurs fictifs peuvent être révoqués ou supprimés automatiquement selon des règles **non lues** |
| Brouillon (« Draft ») | Connecteur « [DRAFT] Draft validation » présent | Disponibilité réelle de la fonction sous licence Communauté : **non vérifiée** |

## 7. API (MCP) : ce qui a été exercé

`get_latest_reports` : fonctionne. `search_intrusion_sets("FIN7")` et `search_malware("Carbanak")` : **échec**, erreur de schéma GraphQL (`x_opencti_score` absent). L'API en écriture et les droits du jeton n'ont pas été exercés. **Rien de ce document ne repose sur l'API seule pour l'interface** : les constats d'interface viennent de la consultation de l'interface elle-même.

## 8. Non vérifié, à lever avant toute écriture

1. Paires de relations autorisées par le schéma (Incident → uses → Attack-Pattern ; Indicator → related-to → Incident ; Sighting).
2. Existence et identifiants des Attack-Patterns T1059.001, T1564.003, T1105, T1053.005, T1046, T1021.001, T1055 (importés par le connecteur MITRE) ; T1070.001 après vérification officielle.
3. Portée et TLP maximal de Google DNS, IPinfo et FIRST EPSS.
4. Filtres du flux `jira` et du connecteur Jira.
5. Règles de déclin des indicateurs et politiques de rétention.
6. Droits du compte qui écrira ; disponibilité de la fonction Brouillon.
7. Entrées complètes du menu Observations (Infrastructures éventuelles).

## 9. Après ingestion (2026-10-06) : relecture par API

Source : GraphQL depuis hiboux (script `octi_ingest.py verify`, `q4.py`), jeton lu dans l'environnement du conteneur, jamais affiché. **Contrôle graphique : exécuté le 2026-10-06 en revue de clôture** (voir `Guide-consultation-OpenCTI.md` pour les réserves : graphe de l'incident non rendu, onglet Indicateurs vide, organisations sans marquage).

| Rubrique | Objets relus | Détail |
|---|---|---|
| Analyses | 1 rapport + 3 notes = 4 | rapport internal-report, 103 objets (85 à l'origine), 7 références, 2 PDF joints (import automatique désactivé) |
| Événements | 1 incident + 4 données observées + 4 détections = 9 | incident du 2026-03-02T08:31Z au 2026-03-07T09:02Z (bornes d'observation) |
| Observations | 27 observables + 8 indicateurs = 35 | 0 artefact, 0 nom de domaine |
| Support | 3 systèmes, 3 organisations, 6 labels, 11 références externes | non comptés comme objets analytiques |
| Relations | 20 étiquetées (8 uses vers 8 techniques, 8 related-to, 4 targets) + 6 based-on + 4 détections | 0 relation sortant de nos observables vers un objet hors mission |

Garde-fous constatés après écriture : 0 nom de domaine créé avec une valeur du challenge ; journaux de Google DNS et IPinfo sans mention de nos plages ; connecteurs d'import de documents silencieux après les pièces jointes ; indicateurs révoqués automatiquement (valid_until passée, voulu). Écart : les entités ATT&CK de production pour T1059.001, T1564.003, T1105, T1053.005, T1046, T1021.001 et T1055 sont des **entités minimales créées par AlienVault** (nom = identifiant), pas des fiches MITRE complètes ; seule T1685.005 est une entité MITRE complète.
