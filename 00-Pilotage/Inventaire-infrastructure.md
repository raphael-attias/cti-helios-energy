# Inventaire de l'infrastructure : capacités réellement constatées

Contrôle du 2026-10-06, depuis le Mac de travail, en lecture seule. Légende des niveaux de preuve :
**V** = vérifié aujourd'hui par une commande, **D** = affirmé par la documentation du vault SOC-Homelab (non revérifié), **N** = non testé.

Rappel de la consigne : outil installé, outil accessible et outil correctement configuré sont trois choses différentes.

## Plateformes

| Plateforme | Adresse (source) | Joignable | Authentifié | Version | Droits / capacités | Verdict |
|---|---|---|---|---|---|---|
| MISP | `https://172.16.208.253` (D) | **V** : page de login HTTP 200 | **N** : aucune clé API trouvée dans les emplacements prévus pour ce travail | v2.5.46 annoncée (D), non relue en direct | inconnus | Accessible, non configuré pour moi |
| Cortex | `https://172.16.171.26` (D) | **V** : `/api/status` HTTP 200 | **N** : pas de clé API | **V** Cortex 4.1.0-1 (Play 3.0.9, Elastic4s 8.19.0), auth par clé ou locale | analyseurs non listés | Accessible, non authentifié |
| OpenCTI | hôte `hiboux`, port 8180 (D) | **V** : HTTP 401 sans jeton | **V** via le serveur MCP `opencti` de la session (lecture) : `get_latest_reports` renvoie des rapports (les plus récents publiés le 2026-10-05) | **6.9.21 confirmée par l'interface** (UI) | lecture seulement via MCP ; `search_intrusion_sets` et `search_malware` **échouent** (erreur GraphQL `x_opencti_score` absent du schéma : décalage client/plateforme) | Lecture partielle par MCP ; **interface consultée en lecture le 2026-10-06** (version 6.9.21 confirmée, édition Communauté, licence d'essai expirée, compte admin) : voir `05-Plateformes/Verification-OpenCTI.md` ; écriture non établie |
| Wazuh | manager/indexeur/dashboard sur `10.99.99.3` (D) | **V** : dashboard HTTPS 443 répond (302) ; **ports 55000 (API) et 9200 (indexeur) injoignables depuis le Mac** | **N** | 4.14.7 annoncée (D) | inconnus | Interface joignable, API non joignable d'ici |
| CrowdSec | sur `piraph` 172.16.0.2 (D) | hôte répond au ping (V) ; ports 8080 et 6060 fermés | **N** | inconnue | aucune fonction pertinente identifiée pour ce challenge | Non utilisé tant qu'aucun usage n'est démontré |
| pharos (SSH) | `rapatt@pharos` | **V** : `ssh-ok` en mode batch | clé SSH fonctionnelle | n/a | passerelle possible vers `adminlan` | Disponible pour des accès indirects, non utilisée |

## Outils locaux (Mac)

| Besoin | Constat | Verdict |
|---|---|---|
| Python | 3.14.7 (V) | OK |
| `pyyaml` | 6.0.3 (V) | OK |
| `stix2`, `stix2-validator` | absents (V) | À installer dans un venv dédié (accord requis) |
| `pymisp` | absent (V) | À installer (accord requis) |
| Validation/conversion Sigma (`pysigma`, `sigma-cli`) | absents (V) | À installer (accord requis) |
| Graphe : `matplotlib`, `networkx`, Graphviz `dot` | absents (V) | À installer (accord requis) |
| PDF : `reportlab`, `weasyprint`, `wkhtmltopdf` | absents (V) | Voir ci-dessous |
| `pandoc` 3.11 + `tectonic` (moteur LaTeX) | présents (V) | Rendu PDF possible mais **non testé** ; tectonic peut télécharger des paquets au premier lancement |
| Google Chrome (impression HTML vers PDF en mode sans interface) | présent (V) | Alternative **non testée** |
| `jq`, `file`, `shasum`, `strings`, `objdump`, `otool` | présents (V) | Utilisables pour l'analyse statique **si** des échantillons étaient fournis |
| `yara`, `capa`, `pefile`, `lief` | absents (V) | Non requis tant qu'il n'y a pas d'échantillon |

## Point d'attention : l'infrastructure est une infrastructure de production

La documentation du vault SOC-Homelab (D) décrit des synchronisations automatiques : MISP vers OpenCTI toutes les 30 minutes, TheHive et MISP toutes les heures (étiquette `thehive:import`), et un connecteur OpenCTI vers Cortex avec garde TLP. Écrire un événement du challenge dans MISP peut donc **polluer le graphe OpenCTI de production** avec des IoC fictifs. De plus, dans OpenCTI, la création d'observables peut déclencher des enrichissements automatiques tiers (Google DNS, IPinfo) et alimenter le flux `jira` public. Le plan d'ingestion tient compte de cette contrainte (voir `99-Historique/Plan-ingestion.md`) et la question a été traitée (B-03 : isolation par organisation et distribution 0, voir `Decisions-et-limites-finales.md`).

## Mise à jour 2026-10-06 (accès via Pharos, Ansible et MCP)

| Plateforme | Chemin d'accès réellement utilisé | Authentification | Opérations réalisées |
|---|---|---|---|
| MISP 2.5.46 (CT 3012, hôte `misp`) | Pharos puis Ansible ciblé (`ansible misp -b`), API en local sur l'hôte | utilisateur dédié `challenge-writer` créé pour la mission (clé en fichier root 0600, jamais affichée) | création d'organisation et d'utilisateur, événement 6, relecture, export STIX |
| OpenCTI 6.9.21 (hôte `hiboux`) | Pharos puis Ansible (`ansible hiboux -b`), GraphQL local | jeton lu dans l'environnement du conteneur de la plateforme à l'exécution (jamais affiché) ; **c'est le jeton d'administration** : écriture non limitée par un compte restreint | écriture ciblée (47 objets étiquetés, relations, détections, rapport, PDF), lectures de configuration |
| Wazuh 4.14.7 (VM 127, hôte `wazuh`) | Pharos puis Ansible (`ansible wazuh -b`) ; API 55000 atteinte depuis le conteneur manager | identifiants lus dans l'environnement du conteneur (non affichés) | conteneur de test isolé ; 2 fichiers de production ; redémarrage ; rejeu API ; lecture de l'indexeur |
| Cortex 4.1.0-1 | non utilisé | - | aucune |
| CrowdSec | non utilisé | - | aucune |
| OpenCTI (interface) | Chrome connecté de l'utilisateur lors de la première consultation ; session expirée ensuite | identifiants non saisis | lecture d'interface (première phase uniquement) |

L'API Wazuh injoignable depuis le Mac n'était pas un blocage : elle est joignable depuis la VM. Commandes enveloppées dans des scripts copiés dans `/tmp` des hôtes (sans secret) et supprimés en fin de session.
