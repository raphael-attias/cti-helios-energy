#!/bin/bash
# Resynchronise le dépôt Git LOCAL déjà créé (cti-helios-energy) avec le dossier de mission, sans rien committer ni pousser.
# Étapes : diff (aperçu, aucune écriture) | sync (copie les fichiers modifiés, réécrit Depot-Git-manifeste.csv, vérifie).
# Ensuite, c'est à l'utilisateur de faire : git add -A && git commit -m "..." && git push   (aucun trailer d'attribution)
# Usage : bash 11-Validation/synchroniser-depot-git.sh <diff|sync> [cible]
set -eu
SRC="$(cd "$(dirname "$0")/.." && pwd)"; STEP="${1:-diff}"; DEST="${2:-/Users/rapatt/Projet/cti-helios-energy}"
EXCL=(
  --exclude='*.bak' --exclude='.DS_Store' --exclude='__pycache__/' --exclude='*.pyc' --exclude='.venv/' --exclude='.obsidian/' --exclude='*.tmp' --exclude='*.swp'
  --exclude='.git/' --exclude='.gitignore' --exclude='AVANT-TOUTE-PUBLICATION.md' --exclude='11-Validation/Depot-Git-manifeste.csv'
  --exclude='*.env' --exclude='*.pem' --exclude='*.key' --exclude='*.pfx' --exclude='*.p12' --exclude='id_rsa*' --exclude='id_ed25519*'
  --exclude='*.exe' --exclude='*.dll' --exclude='*.xlsm' --exclude='*.docm' --exclude='*.zip' --exclude='*.7z' --exclude='*.tgz' --exclude='*.bin' --exclude='*.sys'
)
[ -d "$DEST/.git" ] || { echo "ARRÊT : $DEST n'est pas un dépôt Git"; exit 1; }
case "$STEP" in
 diff) echo "--- fichiers qui changeraient dans $DEST (ajoutés ou modifiés, + supprimés)"; rsync -ani --delete --out-format='%i %n' "${EXCL[@]}" "$SRC/" "$DEST/" | grep -v '/$' | grep -v '^\.' || echo "(aucun écart)";;
 sync)
  rsync -a --delete "${EXCL[@]}" "$SRC/" "$DEST/"
  python3 - "$DEST" <<'PY'
import csv, hashlib, os, sys
d = sys.argv[1]; files = []
for root, dirs, fs in os.walk(d):
    dirs[:] = [x for x in dirs if x != ".git"]
    for f in fs:
        rel = os.path.relpath(os.path.join(root, f), d)
        if rel in (".gitignore", "AVANT-TOUTE-PUBLICATION.md", "11-Validation/Depot-Git-manifeste.csv"): continue
        files.append(rel)
with open(os.path.join(d, "11-Validation", "Depot-Git-manifeste.csv"), "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f); w.writerow(["chemin", "octets", "sha256"])
    for p in sorted(files):
        b = open(os.path.join(d, p), "rb").read(); w.writerow([p, len(b), hashlib.sha256(b).hexdigest()])
print("manifeste d'inclusion réécrit dans le dépôt : %d lignes" % len(files))
PY
  cp -p "$DEST/11-Validation/Depot-Git-manifeste.csv" "$SRC/11-Validation/Depot-Git-manifeste.csv"
  bash "$SRC/11-Validation/verifier-depot.sh" "$DEST" 2>&1 | grep -E "OK|KO|VÉRIF" || true
  echo "--- à committer par vous :"; git -C "$DEST" status --short;;
 *) echo "étape inconnue : $STEP"; exit 2;;
esac
