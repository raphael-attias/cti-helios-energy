# Investigation OpenCTI : état final et vue synthétique

Date : 2026-10-07. Enquête `[CHALLENGE FICTIF] Helios Energy — Investigation CTI`, identifiant `14c28507-2b09-48b8-9b36-c2dc2470d64a`. **Lien** : `http://172.16.0.4:8180/dashboard/workspaces/investigations/14c28507-2b09-48b8-9b36-c2dc2470d64a?mode3D=false&modeTree=null&withForces=false` (le paramètre `withForces=false` affiche la mise en page enregistrée, voir §5). Les modifications ont été faites après approbation explicite de l'utilisateur (le 2026-10-07) et ne portent que sur cette enquête.

## 1. État initial (sauvegardé avant modification)

Sauvegarde : `Investigation-etat-initial.json` (identifiants, types et noms des 56 entités et des 30 relations suivies, description, tags, absence de mise en page : `graph_data` et `manifest` vides). Capture de l'état précédent : `11-Validation/preuves-consultation/opencti-investigation-graphe-vue-arbre.jpg`.

Constats : l'enquête suivait 56 entités et 30 relations existantes, sans mise en page enregistrée : la vue par forces donnait un nuage de nœuds, et la vue en arbre superposait des libellés. Les 20 observables sans lien avec un autre élément et les 4 données observées apparaissaient comme des nœuds isolés sans explication.

## 2. Fonctions réellement utilisées

L'interface 6.9.21 n'offre pas d'outil de mise en page par déplacement qui s'enregistre (un glissement de l'écran déplace seulement la vue). La mise en page est enregistrée par le champ `graph_data` de l'enquête, dont le format a été relevé dans le code de l'interface (base64 du JSON `{identifiant: {id, x, y}}`, écrit par `workspaceFieldPatch`). Script : `octi_investigation_synthese.py` (modes `plan`, `apply`, `verify`). **Aucune entité ni relation n'est créée, modifiée ou supprimée par ce script** ; les relations suivies sont des relations existantes dont les deux extrémités sont dans la sélection.

## 3. Sélection : vue synthétique

Les compléments STIX approuvés le même jour (4 infrastructures, 1 outil créé, 2 outils MITRE reliés, 11 relations ; `octi_stix_complements.py`) ont d'abord été ajoutés à OpenCTI : ils comblent un écart réel entre le bundle et la plateforme (E12 dans `06-STIX-Graphe/Ecarts-bundle-plateformes.md`). L'enquête suit désormais **39 éléments et 43 relations existantes** :

| Élément | Nombre | Pourquoi dans la vue |
|---|---|---|
| Incident | 1 | pivot de la vue |
| Victime et systèmes | 4 | actifs victimes, reliés par `targets` et par les détections |
| Techniques ATT&CK observées | 8 | chaîne d'attaque, reliées à l'incident par `uses` |
| Outils (`powershell.exe`, `schtasks`, `Wevtutil`) | 3 | capacités documentées par le journal brut ou le détail d'alerte |
| Infrastructures (téléchargement, balise, sortie, repli supposé) | 4 | rôles réseau décrits par les alertes |
| Indicateurs historiques (expirés) | 8 | reliés à l'incident par `related-to` (hypothèse) |
| Observables reliés | 7 | 3 fichiers des fiches (déclarés) et 4 URL ou adresses de l'infrastructure |
| Rapport et 3 notes (limites, attribution, registre des alertes) | 4 | explications, hypothèses et limites |

Relations suivies (43) : 17 `uses` (dont 2 relations MITRE de production entre un outil et sa technique), 8 `related-to`, 6 `based-on`, 4 `targets`, 4 détections, 4 `consists-of`.

**Retirés de cette vue seulement, sans suppression de données** : 24 éléments, soit 8 adresses IPv4, 4 données observées, 3 certificats, 4 fichiers, 3 URL, 1 dossier et 1 compte, qui n'ont aucune relation avec un autre élément suivi. Ils restent dans la plateforme (liste filtrée par l'étiquette `challenge:helios-fictif`), dans le rapport (103 objets) et dans le bundle. La description de l'enquête dit cela, avec la légende.

## 4. Mise en page

Deux bandes, de gauche à droite : **bande haute** = techniques | incident | victime et actifs | indicateurs | fichiers des fiches ; **bande basse** = outils puis infrastructure avec ses observables ; **rangée du bas** = rapport et notes. Un indicateur et son observable sont sur la même ligne ; chaque infrastructure a ses observables sous elle. Aucune relation n'a été créée pour l'apparence.

## 5. Hypothèses, limites et attribution

L'outil ne permet pas de colorer un nœud par statut. Le statut est donc porté par : les étiquettes de chaque objet (`analytic:observed`, `analytic:declared-unverified`, `analytic:hypothesis`), la description de l'enquête (hypothèses : lien indicateur vers incident, rôle de repli, rôle de balise ; déclarés : les 3 fichiers des fiches, `schtasks`) et les 3 notes (limites, attribution inconnue, registre des 12 alertes). **Aucun acteur n'est représenté** : le cluster est non attribué ; il n'y a donc aucune attribution visuelle.

## 6. Contrôle dans l'interface (2026-10-07)

| Contrôle | Résultat |
|---|---|
| Sauvegarde persistante | relue par API : 82 identifiants suivis (39 éléments, 43 relations) et 39 positions |
| Réouverture | l'enquête rouverte à froid (nouvelle navigation) affiche la mise en page enregistrée avec `withForces=false` |
| Lisibilité | bandes distinctes, **aucun nœud superposé**, aucun élément isolé (hors notes, voir limites) ; libellés petits au zoom d'ensemble, lisibles en zoomant ; captures `opencti-investigation-finale-vue-ensemble.jpg` et `opencti-investigation-finale-detail.jpg` |
| Navigation vers les objets | un clic sur l'incident ouvre un panneau « objets sélectionnés » avec le lien d'ouverture de la fiche |
| Cohérence | les objets suivis sont ceux du rapport (103 objets) ; les 27 objets de renseignement du bundle ont leur équivalent OpenCTI, sauf la campagne (l'incident en tient lieu) et les 3 malwares des fiches (non créés dans OpenCTI, car non démontrés) |

## 7. Limites

- **La mise en page enregistrée ne s'affiche qu'avec les forces désactivées** (`withForces=false` dans l'adresse, ou l'icône des forces) ; avec les forces actives, OpenCTI recalcule une disposition en étoile autour de l'incident.
- Les libellés sont petits au zoom d'ensemble ; les noms d'indicateurs commencent tous par `[CHALLENGE FICTIF]` et sont tronqués.
- Dans l'interface, **seul le rapport apparaît dans la rangée du bas** : les 3 notes sont suivies mais non dessinées par le graphe d'enquête (comportement constaté, non expliqué).
- Les étiquettes de relation sont masquées au zoom d'ensemble.
- Licence d'essai expirée : la rubrique fonctionne, mais aucune garantie sur les fonctions Enterprise.

## 8. Retour arrière

Restaurer la sélection, la description et l'absence de mise en page depuis `Investigation-etat-initial.json` (`workspaceFieldPatch` sur `investigated_entities_ids`, `description`, `graph_data`). Les objets créés par les compléments STIX se retirent par identifiant (`IDs-complements-T13.json`).
