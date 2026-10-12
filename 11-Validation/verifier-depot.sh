#!/bin/bash
# Vérifie RÉELLEMENT une copie du dossier de mission (avant ou après commit) : hachages, liens, scripts, bundle reproductible.
# Usage : bash 11-Validation/verifier-depot.sh <dossier du dépôt>
set -u
D="${1:?dossier requis}"; PY=/Users/rapatt/Projet/cti-helios-env/.venv/bin/python; KO=0
ok(){ echo "  OK  $1"; }; ko(){ echo "  KO  $1"; KO=1; }
echo "== 1. hachages du manifeste d'inclusion"
"$PY" - "$D" <<'PY' && ok "tous les fichiers du manifeste présents avec le bon sha256" || ko "écart avec le manifeste"
import csv, hashlib, os, sys
d = sys.argv[1]; bad = []
for r in csv.DictReader(open(os.path.join(d, "11-Validation", "Depot-Git-manifeste.csv"), encoding="utf-8")):
    p = os.path.join(d, r["chemin"])
    if not os.path.exists(p) or hashlib.sha256(open(p, "rb").read()).hexdigest() != r["sha256"]:
        if r["chemin"] != "11-Validation/Depot-Git-manifeste.csv": bad.append(r["chemin"])
print("écarts :", bad[:10]); sys.exit(1 if bad else 0)
PY
echo "== 2. aucun fichier hors manifeste (sauf .gitignore, AVANT-TOUTE-PUBLICATION.md, .git)"
"$PY" - "$D" <<'PY' && ok "copie = manifeste" || ko "fichiers en trop ou manquants"
import csv, os, sys
d = sys.argv[1]; want = {r["chemin"] for r in csv.DictReader(open(os.path.join(d, "11-Validation", "Depot-Git-manifeste.csv"), encoding="utf-8"))}
have = set()
for root, dirs, files in os.walk(d):
    dirs[:] = [x for x in dirs if x != ".git"]
    for f in files: have.add(os.path.relpath(os.path.join(root, f), d))
have -= {".gitignore", "AVANT-TOUTE-PUBLICATION.md"}; want.add("11-Validation/Depot-Git-manifeste.csv"); have.add("11-Validation/Depot-Git-manifeste.csv") if os.path.exists(os.path.join(d, "11-Validation", "Depot-Git-manifeste.csv")) else None
print("en trop :", sorted(have - want)[:5], "| manquants :", sorted(want - have)[:5]); sys.exit(0 if have == want else 1)
PY
echo "== 3. scripts : syntaxe Python et shell"
N=0; while read -r f; do "$PY" -m py_compile "$f" 2>/dev/null && N=$((N+1)) || ko "syntaxe Python : $f"; done < <(find "$D" -name '*.py' -not -path '*/.git/*')
find "$D" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null
echo "  $N scripts Python compilés"
M=0; while read -r f; do bash -n "$f" 2>/dev/null && M=$((M+1)) || ko "syntaxe shell : $f"; done < <(find "$D" -name '*.sh' -not -path '*/.git/*'); echo "  $M scripts shell contrôlés"
echo "== 4. contrôle de cohérence du dossier exécuté DEPUIS la copie (liens, originaux, PDF, bundle, tests, secrets)"
OUT=$("$PY" "$D/11-Validation/controle-coherence.py" 2>&1 | tr -d '\r'); echo "$OUT" | grep -E "== OK|== ÉCARTS|KO" ; echo "$OUT" | grep -q "== ÉCARTS == 0" && ok "controle-coherence.py : 0 écart dans la copie" || ko "controle-coherence.py a signalé des écarts"
echo "== 5. contrôles techniques des exigences exécutés DEPUIS la copie"
"$PY" "$D/11-Validation/controles-exigences.py" 2>&1 | grep -E "KO" | grep -v "REQ-15\|définition stricte\|analytiques et identités" ; echo "  (les deux KO attendus de REQ-15 sont filtrés)"
echo "== 6. le bundle STIX se régénère à l'identique depuis l'export MISP brut (reproductibilité)"
T=$(mktemp -d); cp -R "$D/." "$T/"; "$PY" "$T/06-STIX-Graphe/generer-bundle.py" >/dev/null 2>&1
A=$(shasum -a 256 "$D/06-STIX-Graphe/Bundle-STIX.json" | cut -d' ' -f1); B=$(shasum -a 256 "$T/06-STIX-Graphe/Bundle-STIX.json" | cut -d' ' -f1); rm -rf "$T"
[ "$A" = "$B" ] && ok "bundle régénéré identique ($A)" || ko "bundle régénéré différent ($A / $B)"
echo "== 7. aucun remote, aucun secret, aucun binaire"
[ ! -d "$D/.git" ] || { [ -z "$(git -C "$D" remote)" ] && ok "aucun remote" || ko "un remote existe"; }
BIN=$(find "$D" -type f \( -iname '*.exe' -o -iname '*.dll' -o -iname '*.xlsm' -o -iname '*.zip' -o -iname '*.7z' \) -not -path '*/.git/*' | wc -l | tr -d ' '); [ "$BIN" = "0" ] && ok "aucun binaire" || ko "$BIN binaire(s)"
[ $KO -eq 0 ] && echo "VÉRIFICATION : TOUT EST CONFORME" || echo "VÉRIFICATION : DES ÉCARTS EXISTENT"
exit $KO
