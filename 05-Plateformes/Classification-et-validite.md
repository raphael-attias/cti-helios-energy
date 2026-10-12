# Classification, diffusion et validité : état et propositions

Date : 2026-10-06. **État au 2026-10-07 : P1 appliquée après approbation ; P2, P3 et P4 non appliquées (arbitrages Q29 et Q32 non obtenus, voir `00-Pilotage/Decisions-et-limites-finales.md`).** Principe : un marquage TLP est une **étiquette de traitement** (convention) ; seule la **diffusion MISP** et les droits des comptes restreignent réellement l'accès. Les objets sont fictifs et ne doivent circuler nulle part : le niveau le plus strict (TLP:RED) est le choix cohérent.

## 1. État actuel et proposition par objet

| Objet | État actuel | Proposition | Argument |
|---|---|---|---|
| Événement MISP 6 | diffusion « organisation seulement » (0), non publié, tag `tlp:amber` (seuls `tlp:amber` et `tlp:clear` existent dans MISP) | **garder la diffusion 0** ; remplacer le tag par `tlp:red` si un administrateur le crée à partir de la taxonomie TLP | la diffusion 0 est ce qui empêche les comptes d'une autre organisation (dont ceux du connecteur OpenCTI : id 4, organisation 1, rôle lecture seule, **vérifié : il ne voit pas l'événement 6**) de le lire ; le tag n'ajoute aucune restriction technique |
| Rapport OpenCTI | TLP:RED, étiquettes de mission, auteur « Dossier pédagogique » | **inchangé** | contient une synthèse de limites, pas de donnée sensible réelle ; RED évite toute exportation involontaire |
| Incident OpenCTI | TLP:RED, étiquettes | **inchangé** | idem |
| Notes (3) | TLP:RED, étiquettes | **inchangé** | cohérence avec le rapport |
| Indicateurs (8) | TLP:RED, expirés, révoqués, détection désactivée, score 20 | **inchangé** | voir 3 |
| Observables, données observées, détections, relations | TLP:RED, étiquettes | **inchangé** | |
| Organisations (3) : « Équipe CTI », « Dossier pédagogique », « Helios Energy (fictif) » | **aucun marquage, aucune étiquette** | **fait le 2026-10-07 après approbation : étiquette `challenge:helios-fictif` et marquage TLP:RED sur les 3** (relu par API) ; variante prudente : étiquette seule | elles sont **propres à la mission** (créées par l'ingestion à 10:07:51 ; 0 relation pour les deux auteurs qui sont auteurs de 5 et 42 objets, 1 relation `targets` pour la victime) : le changement n'affecte aucun objet d'autre usage. Sans étiquette elles échappent au filtre de retrait. Avec un marquage RED, un utilisateur sans habilitation RED verrait l'auteur masqué (comportement normal d'OpenCTI) |
| Systèmes (3) | TLP:RED, étiquettes | inchangé | |
| Bundle STIX local | TLP:AMBER sur les objets ajoutés, 72 objets sans marquage | Q29 non tranchée : le bundle garde TLP:AMBER (P4 non appliquée) | cohérence documentaire, aucune écriture de production |

## 2. Différences de diffusion entre plateformes

| Plateforme | Ce qui restreint réellement | Ce qui est seulement déclaratif |
|---|---|---|
| MISP | **diffusion de l'événement** (0 = organisation propriétaire) et organisation des comptes ; les administrateurs du site voient tout | tags TLP |
| OpenCTI 6.9.21 Communauté (licence d'essai expirée) | **marquages** par rapport à l'habilitation maximale des utilisateurs ; **pas de partage par organisation** (fonction de l'édition Enterprise, désactivée) ; l'administrateur voit tout | étiquettes `challenge:*` |
| Wazuh | droits d'accès au dashboard et à l'indexeur ; aucune notion de TLP | groupe de règles `helios_challenge` |

Conséquence : aucune des trois plateformes n'isole les données de la mission d'un administrateur ; l'isolation est celle de MISP (diffusion 0) et la prudence d'OpenCTI repose sur les marquages.

## 3. Indicateurs expirés : choix et effet

Choix actuel : `valid_until` = 2026-04-02 (un mois après l'incident, déjà passé), score 20, détection désactivée ; OpenCTI les a marqués **révoqués**. Raison : ces indicateurs viennent d'un dossier d'exercice (plages de documentation RFC 5737, domaines `.test`) et ne doivent déclencher aucune détection ni être poussés vers un SIEM, un pare-feu ou un flux.

| Effet | Constat |
|---|---|
| Consultation | **visibles** dans les listes (filtre par étiquette : 8) et reliés à l'incident, au rapport et aux détections ; marqués révoqués |
| Détection et flux | **exclus** : `x_opencti_detection = false` ; aucun flux live ni connecteur de sortie ne les reprend (le flux `jira` public filtre sur un libellé qui n'est pas porté par nos objets) |
| MISP | aucun indicateur : tous les attributs ont `to_ids = false` |
| Wazuh | aucun lien automatique avec les indicateurs OpenCTI |

**Je ne propose pas de les rendre actifs** : cela les ferait entrer dans les mécanismes de détection et de diffusion de l'infrastructure existante, pour un simple gain d'affichage. Si le commanditaire veut les voir « valides », la seule voie raisonnable est d'ajuster `valid_from` (E2 dans `06-STIX-Graphe/Ecarts-bundle-plateformes.md`, Q32) en gardant `valid_until` passée.

## 4. Changements : état final (P1 faite, P2 à P4 non appliquées)

| # | Changement | Cible exacte | Effet | Retour arrière |
|---|---|---|---|---|
| P1 | Étiquette et marquage RED des 3 organisations | OpenCTI : ids `6448890f-906c-4c33-8494-6281c72d17b1`, `de91dc76-bd49-421c-b6e6-868cb511870e`, `5c7aeff2-a19c-431a-8e67-1fd2644c53cb` | filtre de retrait complet ; auteurs masqués aux non habilités | retirer l'étiquette et le marquage |
| P2 | Tag `tlp:red` sur l'événement MISP 6 à la place de `tlp:amber` | MISP événement 6 ; **prérequis** : un administrateur crée `tlp:red` (n'existe pas) | alignement MISP/OpenCTI | remettre `tlp:amber` |
| P3 | `valid_from` par indicateur | OpenCTI : 8 indicateurs (ids dans `IDs-cibles-retrait.json`) | cohérence avec le bundle | remettre 2026-03-02T08:30Z |
| P4 | Régénérer le bundle en TLP:RED | local | cohérence documentaire | aucun besoin |
