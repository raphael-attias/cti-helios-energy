# Insertion directe de l'organisation MISP en base

Date de l'opération : 2026-10-06, vers 09:58 UTC (la ligne porte `date_created` 09:59:53 d'après l'horloge de la base). Date de cette fiche : 2026-10-06. **Aucune nouvelle écriture directe en base n'a été faite pendant la revue** : les contrôles ci-dessous sont des `SELECT` et un `CHECK TABLE`.

## 1. Motif

Obtenir une **organisation propriétaire distincte** pour l'événement de la mission : c'est ce qui rend l'événement invisible aux comptes d'intégration de l'organisation 1 (décision DEC-021, après DEC-010 : un label ou une distribution ne sont pas une isolation). Une organisation locale ne pouvait pas être créée par un compte Publisher.

## 2. Méthode

1. Lecture de l'état avant : organisations `[1:stormlab]`, utilisateurs d'id 1 à 4.
2. **Un seul `INSERT INTO organisations (...)`** exécuté dans le conteneur de base `misp-docker-db-1` (script `misp_setup_org.sh` joué via Ansible, identifiants lus dans l'environnement du conteneur, non affichés), écrivant : nom `CHALLENGE-FICTIF`, dates, description « Organisation fictive : challenge CTI Helios (donnees fictives) », `local = 1`, `created_by = 1`, `uuid = UUID()` de MySQL, champs de type, nationalité, secteur, contacts vides. Condition `WHERE NOT EXISTS` pour éviter un doublon à la relance.
3. Création de l'utilisateur par la **commande applicative** `cake user create challenge-writer@helios.test 4 2` (rôle 4 = Publisher, organisation 2) puis `cake user change_authkey` ; la clé a été écrite dans un fichier root 0600 sur l'hôte, **supprimé depuis** (absence vérifiée le 2026-10-06).
4. Lecture de l'état après : organisations `[2:CHALLENGE-FICTIF, 1:stormlab]`, utilisateurs d'id 1 à 5.

**Pourquoi pas l'API ou l'interface** : la création d'organisation par l'API demande la clé d'un administrateur du site, que je n'ai pas utilisée ; la console `cake` ne propose pour les organisations que `organisation list` (vérifié) ; l'interface web demandait la session de l'utilisateur. Le choix du SQL était donc **le moyen le plus court, pas le plus propre** ; l'alternative correcte (formulaire d'administration) existait via la session de l'utilisateur et aurait laissé une trace d'audit applicative. Cette alternative n'a pas été demandée à l'époque : c'est une réserve assumée.

## 3. Contrôles d'intégrité réalisés (2026-10-06, lecture seule)

| Contrôle | Résultat |
|---|---|
| Ligne de l'organisation 2 | `local = 1`, `created_by = 1`, uuid `ad95f307-c16c-11f1-b785-3ec53bff7a0f` (**UUID de version 1**, produit par `UUID()` de MySQL : cause de l'avertissement « non UUIDv4 » du validateur STIX sur l'identité MISP), `type` vide (l'organisation 1 a le type `ADMIN`) |
| `CHECK TABLE organisations` | `OK` |
| Auto-incrément | organisations 3, utilisateurs 6, événements 7 : pas de trou ni de collision |
| Références à l'organisation 2 | 1 utilisateur (id 5), 1 événement (`org_id` et `orgc_id` = 2), 46 attributs via cet événement ; 0 groupe de partage, 0 serveur de synchronisation |
| Utilisateur 5 | organisation 2, rôle 4 (Publisher), non désactivé, `change_pw = 1`, `date_created` vide (comportement de la commande) |
| Événements des autres organisations | inchangés (événements 1 à 5 de l'organisation 1) |
| Visibilité | le compte du connecteur OpenCTI (id 4, organisation 1, lecture seule, pas administrateur) interrogé en lecture : **l'événement 6 n'est pas visible** |
| Interface | l'organisation s'affiche avec son nom dans l'événement 6 ; aucune erreur d'affichage |

## 4. Limites

- L'écriture directe **contourne les validations de l'application** (champs obligatoires, cache applicatif) et **n'apparaît pas dans le journal d'audit de MISP** pour cette ligne. Le cache applicatif des organisations n'a pas été vidé ; aucun effet constaté (l'organisation s'affiche).
- Champs laissés vides ou par défaut : `type`, `nationality`, `sector`, `contacts`, `date_modified` (identique à la création).
- Le `check` ne détecte pas ce qu'une montée de version de MISP pourrait attendre d'une organisation créée hors application : non testé.
- Aucune sauvegarde de la base n'a été faite avant l'insertion (pas de sauvegarde exigée par le périmètre ; elle serait un prérequis avant un retrait).

## 5. Procédure de retour arrière (préparée, NON EXÉCUTÉE)

Ordre à respecter ; **aucune de ces étapes n'utilise d'écriture SQL directe** :

1. Sauvegarder la base MISP (`mysqldump` de la base `misp`, fichier hors du dossier de mission) : confirmation requise.
2. Bloquer l'utilisateur 5 et supprimer sa clé d'API : console `cake user block challenge-writer@helios.test` puis suppression de la clé dans Administration > Utilisateurs (ou API d'administration).
3. Supprimer l'événement 6 : interface (suppression, puis purge de la corbeille si souhaité) ou API d'administration, **après** le retrait côté OpenCTI si l'on veut garder la traçabilité.
4. Supprimer l'utilisateur 5 : interface d'administration.
5. Supprimer l'organisation 2 : interface d'administration (Administration > Liste des organisations). MISP refuse la suppression tant que des utilisateurs ou événements y sont rattachés : c'est le garde-fou voulu.
6. Vérifier : `cake organisation list` ne montre que l'organisation 1 ; `SELECT COUNT(*)` sur `events`, `users`, `organisations` ; l'auto-incrément ne revient pas en arrière (les identifiants 2 et 5 ne seront pas réutilisés), sans conséquence.

Secours si l'interface refuse (à n'utiliser qu'avec un accord explicite, car c'est une écriture directe) : `DELETE FROM organisations WHERE id = 2` **uniquement après** vérification que les comptes de références du tableau 3 sont tous à zéro.
