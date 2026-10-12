# Dépôt Git `cti-helios-energy` : procédure exacte (à exécuter par l'utilisateur)

Date : 2026-10-06. Exigence REQ-36 (obligatoire). **Un essai à blanc ne valide pas l'exigence** : elle n'est satisfaite qu'après création réelle et vérification réelle du dépôt.

## 1. Opération demandée

| Point | Valeur |
|---|---|
| Cible | `/Users/rapatt/Projet/cti-helios-energy` |
| Cible libre ? | **oui** : le chemin n'existe pas (contrôlé par `preflight` ; aucune autre copie du nom `cti-helios-energy` dans `~/Projet`) ; le script refuse d'écraser quoi que ce soit |
| Source | `/Users/rapatt/Projet/obsi-vault/LPTF-DOC/Challenge-CTI-doc` (le vault n'est pas modifié) |
| Dépôt | **local uniquement, branche `main`, aucun remote, aucun `push`** : le script n'en contient aucun |
| Identité des commits | configuration Git globale existante (`raphael-attias`) |

## 2. Étapes distinctes (une approbation couvre 1 à 4, jamais 5)

| # | Étape | Commande | Effet |
|---|---|---|---|
| 0 | Vérification préalable (déjà faite, refaite juste avant la copie) | `bash 11-Validation/preparer-depot-git.sh preflight` | cible libre ; liste des fichiers ; scan de secrets ; manifeste `Depot-Git-manifeste.csv` ; **aucune écriture dans la cible** |
| 1 | **Copie** | `... copy` | crée le dossier cible et y copie les fichiers retenus ; ajoute `.gitignore` et `AVANT-TOUTE-PUBLICATION.md` |
| 2 | **Vérification de la copie** (avant tout Git) | `... verify` | hachages du manifeste, absence de fichier en trop, syntaxe de tous les scripts Python et shell, **`controle-coherence.py` exécuté depuis la copie** (liens, originaux, PDF, bundle, secrets), `controles-exigences.py` depuis la copie, **régénération du bundle STIX à l'identique** |
| 3 | **Initialisation** | `... init` | `git init -b main` ; vérifie qu'aucun remote n'existe |
| 4 | **Commit local initial** | `... commit` | un seul commit ; message en français |
| 5 | **Publication** | **non couverte, jamais exécutée** | exige un accord explicite distinct et la relecture de `AVANT-TOUTE-PUBLICATION.md` |

Après l'étape 4, vérification finale : `verify` rejoué sur le dépôt, `git status` propre, `git remote -v` vide, nombre de fichiers suivis = manifeste.

## 3. Manifeste d'inclusion (état du 2026-10-06, régénéré à l'étape 0)

190 fichiers à la dernière exécution (le nombre varie légèrement : le manifeste est régénéré par `preflight`). Liste complète avec taille et sha256 : `11-Validation/Depot-Git-manifeste.csv`.

**Inclus** : `fourniture/` (7 artefacts d'origine, texte seulement, nécessaires à la vérification des originaux et à la régénération du bundle) ; `02-Artefacts/` (inventaires dérivés) ; `11-Validation/preuves-consultation/` (12 captures d'interface, utiles comme preuves).

**Exclus** : sauvegardes `*.bak` (3 versions antérieures de la matrice) ; `.DS_Store`, `__pycache__`, `*.pyc`, `.venv`, `.obsidian`, fichiers temporaires ; clés, certificats et fichiers `.env` ; **tout binaire, archive ou document Office** (`*.exe`, `*.dll`, `*.xlsm`, `*.docm`, `*.zip`, `*.7z`, `*.tgz`, `*.bin`) : aucun n'existe dans le dossier (vérifié) ; aucun échantillon suspect ; aucun secret (scan par expressions régulières : aucun motif trouvé hors les scripts qui contiennent l'expression elle-même).

Variante si vous préférez exclure `fourniture/` et les captures : dites-le avant la copie ; dans ce cas la vérification de reproductibilité (étape 2, bundle régénéré) et `controle-coherence.py` ne pourront pas s'exécuter dans le dépôt (elles dépendent de `fourniture/`).

## 4. Répétition à blanc déjà faite (hors du chemin cible)

Copie vers un dossier temporaire puis `verify` : hachages conformes, 34 scripts Python et 6 scripts shell compilent, `controle-coherence.py` exécuté depuis la copie : 0 écart sur 42 contrôles, bundle régénéré à l'identique, verdict « TOUT EST CONFORME ». Deux écarts avaient été trouvés à la première répétition puis corrigés (manifeste lui-même listé en trop ; tableau de bord non encore à jour). La répétition ne vaut pas validation : le dépôt réel n'existe pas encore.

## 5. État au 2026-10-07 : création non approuvée

Le dépôt est **obligatoire depuis le sujet initial** (REQ-36). Sa création locale a été soumise à approbation le 2026-10-07 (deux demandes) et **n'a pas été approuvée** : le chemin `/Users/rapatt/Projet/cti-helios-energy` n'existe pas et rien n'y a été écrit. REQ-36 est **NON SATISFAIT**, cause : création non approuvée. Un essai à blanc (`preflight`) ne vaut pas création. Le script refuse d'écraser quoi que ce soit et ne contient aucun `push`.

## 6. Commandes (à ne lancer qu'avec un accord explicite, dans cet ordre, une par une)

Depuis le dossier de mission `/Users/rapatt/Projet/obsi-vault/LPTF-DOC/Challenge-CTI-doc`.

1. `bash 11-Validation/preparer-depot-git.sh preflight` : vérification préalable, aucune écriture dans la cible.
2. `bash 11-Validation/preparer-depot-git.sh copy` : copie.
3. `bash 11-Validation/preparer-depot-git.sh verify` : doit finir par « TOUT EST CONFORME ».
4. `bash 11-Validation/preparer-depot-git.sh init` : `git init -b main`, aucun remote.
5. `bash 11-Validation/preparer-depot-git.sh commit` : un commit local.
6. Contrôle final : `git -C /Users/rapatt/Projet/cti-helios-energy status --short` (vide), `git -C ... remote -v` (vide), `git -C ... log --oneline` (un commit).

Aucun remote et aucun push sans accord distinct et traitement de `AVANT-TOUTE-PUBLICATION.md`.

## 7. Après création

`verify` est rejoué sur le dépôt réel (hachages, scripts, contrôle de cohérence exécuté depuis le dépôt, bundle régénéré à l'identique, aucun remote, aucun binaire) ; REQ-36 ne passe à « satisfait et contrôlé » qu'après ce contrôle réel.
