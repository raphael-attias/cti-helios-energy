# Vérification TheHive : pourquoi on n'y voit rien

Contrôle du 2026-10-07, **lecture seule** (aucune création, aucune modification, aucun redémarrage). TheHive 5.7.6-1 sur l'hôte `thehive` (172.16.0.184), accès par Pharos puis le compte d'intégration existant `opencti-integration` (profil analyste, organisation `rapatt`), dont la clé est lue dans l'environnement du conteneur du connecteur et n'est jamais affichée ni archivée.

## Conclusion

**Je ne vois rien dans TheHive parce que TheHive n'a pas été utilisé pour cette mission : aucun case, aucune alerte et aucun observable Helios n'y a été créé ni importé, et aucun chemin automatique n'aurait dû en créer.** Ce n'est pas un défaut d'affichage, ni un filtre erroné, ni une restriction de licence.

## Ce qui a été vérifié

| Contrôle | Résultat |
|---|---|
| Organisations visibles par le compte | une seule : `rapatt` ; le compteur de licence donne aussi 1 organisation |
| Contenu de l'organisation | 122 cases (**0 clos**, donc aucun archivage ne masque quoi que ce soit), 70 397 alertes, 251 661 observables |
| Cases et alertes dont le titre, la description ou les étiquettes contiennent `helios`, `INC-2026-0302` ou `fictif` | **0** |
| Terme `challenge` (étiquette `challenge:helios-fictif` incluse) | 0 case ; 19 alertes de production sans lien avec la mission (CVE du noyau de l'hôte `elk`, requêtes web 400 sur `piraph`) qui contiennent le mot dans leur description |
| Observables dont la valeur contient `cdn-svc-update.test`, `198.51.100.24`, `203.0.113.28`, `svchost_update.exe`, les sha256 de BIN-001 ou BIN-002 | **0** pour chacune des six valeurs |
| Fenêtres d'écriture de la mission (2026-10-06 09:50 à 12:30 UTC ; 2026-10-07 10:50 à 11:10 UTC) | 0 case créé ; 792 puis 93 alertes créées, dont les titres sont de la supervision matérielle (`[HW] ...`) ou de la supervision de TheHive ; aucune ne contient `helios` |
| Chemin Wazuh vers TheHive | seuil de niveau 10 ; les règles Helios sont aux niveaux 4 à 7 ; `integrations.log` du manager : **0 mention** de Helios |
| Chemin MISP vers TheHive | l'import est limité à l'étiquette `thehive:import` (étiquette 75) ; elle n'est portée que par l'événement 5 (recette du 19/09) ; **l'événement 6 de la mission ne la porte pas** (ses 9 étiquettes : `tlp:amber` et 8 galaxies) |
| Chemin OpenCTI vers TheHive | le connecteur est **à sens unique TheHive vers OpenCTI** (étiquette autorisée : `wazuh`) ; aucune exportation d'OpenCTI vers TheHive n'existe, et la mission n'en a pas créé |
| Licence | `/api/status` : licence **invalide** (`no-license`, plan « No », expirée, quotas à 0 pour des usages en cours) : c'est l'origine du bandeau que vous voyez. **Elle n'empêche pas** la création d'alertes (93 alertes créées le 2026-10-07 entre 10:50 et 11:10) ni leur lecture : elle n'explique donc pas l'absence |

## Causes examinées

| Cause possible | Verdict |
|---|---|
| Aucun objet créé | **retenue** : preuves ci-dessus |
| Objet présent dans une autre organisation | **écartée dans le périmètre accessible** : une seule organisation existe pour la plateforme (licence et liste concordantes) |
| Recherche ou filtre incorrect | **écartée** : la même recherche faite par l'API (titre, description, étiquette) renvoie 0, et un contrôle positif (terme `RECETTE`) renvoie 8 cases et 32 alertes : la recherche fonctionne |
| Droits insuffisants | **écartée** : le compte voit des centaines de milliers d'objets de l'organisation ; la même absence est constatée avec ses droits |
| Archivage ou statut masquant | **écartée** : aucun case clos |
| Intégration non exécutée ou erreur d'import | **sans objet** : aucun chemin automatique n'était censé transporter des objets Helios (voir les trois chemins) |
| Restriction de licence | **écartée** comme cause (voir la ligne Licence) |

## Incertitude restante

- La capture de l'utilisateur ne montre pas l'organisation sélectionnée dans l'interface : si c'était l'organisation d'administration de la plateforme (qui ne contient pas de cases), le résultat vide serait aussi attendu. Cela ne change rien à la conclusion : le même résultat vide est obtenu dans l'organisation qui contient les données.
- Une lecture directe d'Elasticsearch ou de Cassandra n'a pas été faite (authentification requise ; aucun identifiant n'a été recherché pour la contourner). La conclusion repose sur l'API et sur l'absence de chemin d'import.

## Ce qui n'a pas été fait

Aucun case n'a été créé pour rendre l'affirmation vraie. Si l'utilisation de TheHive pour cette mission devait un jour être voulue (un case d'incident `INC-2026-0302`), ce serait une opération distincte à approuver avec son contenu exact : elle n'est pas proposée, car la mission n'en a pas besoin et le dossier n'en dépend pas. **TheHive ne figure donc pas dans les outils utilisés de la mission.**
