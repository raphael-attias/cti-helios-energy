#!/bin/bash
# Constitution du dépôt Git LOCAL « cti-helios-energy » (exigence REQ-36). AUCUNE PUBLICATION : ce script ne configure jamais de remote
# et n'exécute jamais `git push`. Étapes séparées, à lancer une par une :
#   preflight  : vérifie que la cible est libre, liste les fichiers retenus et exclus, scanne les secrets, écrit Depot-Git-manifeste.csv (aucune écriture hors du manifeste)
#   copy       : copie les fichiers retenus vers la cible (refuse si la cible existe)
#   verify     : vérifie la copie (hachages, liens, scripts, reproductibilité du bundle) via verifier-depot.sh
#   init       : git init -b main dans la cible (aucun remote)
#   commit     : un commit local initial
# Usage : bash 11-Validation/preparer-depot-git.sh <étape> [cible]    (cible par défaut : /Users/rapatt/Projet/cti-helios-energy)
set -eu
SRC="$(cd "$(dirname "$0")/.." && pwd)"
STEP="${1:-preflight}"; DEST="${2:-/Users/rapatt/Projet/cti-helios-energy}"
PY=/Users/rapatt/Projet/cti-helios-env/.venv/bin/python
EXCL=(
  --exclude='*.bak' --exclude='.DS_Store' --exclude='__pycache__/' --exclude='*.pyc' --exclude='.venv/' --exclude='.obsidian/' --exclude='*.tmp' --exclude='*.swp'
  --exclude='11-Validation/Depot-Git-manifeste.csv' --exclude='*.env' --exclude='*.pem' --exclude='*.key' --exclude='*.pfx' --exclude='*.p12' --exclude='id_rsa*' --exclude='id_ed25519*'
  --exclude='*.exe' --exclude='*.dll' --exclude='*.xlsm' --exclude='*.docm' --exclude='*.zip' --exclude='*.7z' --exclude='*.tgz' --exclude='*.bin' --exclude='*.sys'
)
list() { rsync -an --out-format='%n' "${EXCL[@]}" "$SRC/" /nonexistent-target-dryrun/ 2>/dev/null | grep -v '/$' | grep -v '^$' | sort; }
case "$STEP" in
 preflight)
  echo "Source : $SRC"; echo "Cible  : $DEST"
  if [ -e "$DEST" ]; then echo "ARRÊT : $DEST existe déjà (rien à écraser n'est permis)."; exit 1; fi
  [ -d "$(dirname "$DEST")" ] || { echo "ARRÊT : le dossier parent n'existe pas."; exit 1; }
  echo "cible libre : oui"
  list > /tmp/_depot_liste.txt; echo "fichiers retenus : $(wc -l < /tmp/_depot_liste.txt)"
  echo "--- exclus présents dans la source (non copiés)"; find "$SRC" \( -name '*.bak' -o -name '.DS_Store' -o -name '__pycache__' -o -name '*.pyc' \) | sed "s#$SRC/##"
  echo "--- extensions retenues"; sed 's/.*\.//' /tmp/_depot_liste.txt | sort | uniq -c | sort -rn
  echo "--- binaires, archives, documents Office parmi les retenus (doit être vide)"; grep -iE '\.(exe|dll|xlsm|docm|zip|7z|tgz|bin|sys)$' /tmp/_depot_liste.txt || echo "(aucun)"
  echo "--- secrets (jetons, mots de passe, clés privées) parmi les retenus"
  BAD=0
  while read -r f; do
    if grep -IEq '(api[_-]?key|token|secret|passw(or)?d)[" ]*[:=][" ]*[A-Za-z0-9/+_.-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY|Bearer +[A-Za-z0-9._-]{20,}' "$SRC/$f" 2>/dev/null; then
      case "$f" in 11-Validation/controle-coherence.py|11-Validation/preparer-depot-git.sh|11-Validation/verifier-depot.sh) ;; *) echo "SUSPECT : $f"; BAD=1;; esac
    fi
  done < /tmp/_depot_liste.txt
  [ $BAD -eq 0 ] && echo "aucun motif de secret (hors les scripts qui contiennent l'expression régulière elle-même)" || { echo "ARRÊT : motif de secret détecté"; exit 1; }
  "$PY" - "$SRC" <<'PY'
import csv, hashlib, os, sys
src = sys.argv[1]; files = [l.strip() for l in open("/tmp/_depot_liste.txt", encoding="utf-8") if l.strip()]
with open(os.path.join(src, "11-Validation", "Depot-Git-manifeste.csv"), "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f); w.writerow(["chemin", "octets", "sha256"])
    for p in files:
        b = open(os.path.join(src, p), "rb").read(); w.writerow([p, len(b), hashlib.sha256(b).hexdigest()])
print("manifeste d'inclusion écrit : 11-Validation/Depot-Git-manifeste.csv (%d lignes)" % len(files))
PY
  echo "PREFLIGHT OK : aucune écriture dans la cible."; rm -f /tmp/_depot_liste.txt;;
 copy)
  [ ! -e "$DEST" ] || { echo "ARRÊT : $DEST existe déjà."; exit 1; }
  [ -f "$SRC/11-Validation/Depot-Git-manifeste.csv" ] || { echo "ARRÊT : lancer d'abord preflight (manifeste absent)"; exit 1; }
  mkdir -p "$DEST"; rsync -a "${EXCL[@]}" "$SRC/" "$DEST/"; cp -p "$SRC/11-Validation/Depot-Git-manifeste.csv" "$DEST/11-Validation/Depot-Git-manifeste.csv"
  cat > "$DEST/.gitignore" <<'GI'
.DS_Store
__pycache__/
*.pyc
.venv/
.obsidian/
*.env
*.pem
*.key
*.pfx
*.bak
# aucun binaire, archive ou échantillon dans ce dépôt
*.exe
*.dll
*.xlsm
*.docm
*.zip
*.7z
*.tgz
GI
  cat > "$DEST/AVANT-TOUTE-PUBLICATION.md" <<'PUB'
# Avant toute publication de ce dépôt

Ce dépôt est **local**. Il n'a aucun remote et rien n'a été poussé. Avant de le publier ou de le partager :

1. Faire valider par le commanditaire la redistribution de `fourniture/` (artefacts d'origine du sujet) et de `02-Artefacts/` (inventaires dérivés).
2. Relire `11-Validation/preuves-consultation/` : captures d'interfaces internes (nom de compte, noms d'hôtes, adresses du laboratoire) ; les retirer si nécessaire.
3. Relire `05-Plateformes/` : scripts et identifiants d'objets de plateformes internes.
4. Relancer `bash 11-Validation/preparer-depot-git.sh preflight` pour le scan de secrets, puis vérifier l'historique Git.
5. Aucune ouverture publique sans l'accord explicite du commanditaire.
PUB
  echo "copie faite vers $DEST ($(find "$DEST" -type f | wc -l | tr -d ' ') fichiers)";;
 verify) bash "$SRC/11-Validation/verifier-depot.sh" "$DEST";;
 init)
  [ -d "$DEST" ] && [ ! -d "$DEST/.git" ] || { echo "ARRÊT : cible absente ou déjà initialisée"; exit 1; }
  git -C "$DEST" init -q -b main; echo "dépôt initialisé (branche main) ; remotes : [$(git -C "$DEST" remote)] (doit être vide)";;
 commit)
  [ -z "$(git -C "$DEST" remote)" ] || { echo "ARRÊT : un remote est configuré"; exit 1; }
  git -C "$DEST" add -A
  git -C "$DEST" commit -q -m "Challenge CTI Helios Energy (fictif) : rendu final de clôture de la mission" -m "Dépôt local. Aucune publication. Voir AVANT-TOUTE-PUBLICATION.md et 11-Validation/Cloture-finale-mission.md."
  git -C "$DEST" log --oneline | head -3; git -C "$DEST" status --short | wc -l | xargs echo "fichiers non suivis ou modifiés après commit :";;
 *) echo "étape inconnue : $STEP"; exit 2;;
esac
