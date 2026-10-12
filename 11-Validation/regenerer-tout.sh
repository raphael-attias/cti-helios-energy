#!/bin/bash
# Les PDF régénérés sont ceux dont le Markdown a changé pendant la revue (le rendu PDF n'est pas déterministe : métadonnées de date) ; les autres PDF ne sont pas refaits.
# Régénération complète et ordonnée des livrables calculés (local uniquement, aucune écriture en production).
set -eu
B="$(cd "$(dirname "$0")/.." && pwd)"; PY=/Users/rapatt/Projet/cti-helios-env/.venv/bin/python; cd "$B"
bash 11-Validation/regenerer-stix.sh
"$PY" 04-Analyse/generer-timeline.py
"$PY" 07-Detection-Tests/tester-sigma.py > /dev/null && echo "tests Sigma rejoués"
"$PY" 11-Validation/maj-matrice.py | head -3
"$PY" 11-Validation/generer-exigences-origine.py
"$PY" 08-Rapports/composer-rapport-tactique.py | tail -1
"$PY" 10-Soutenance/generer-support.py | tail -1
"$PY" 11-Validation/generer-pdf.py 01-Cadrage/Note-cadrage.md 08-Rapports/Note-partage-communautaire.md 08-Rapports/Rapport-strategique.md 08-Rapports/Rapport-tactique.md 08-Rapports/Note-reglementaire-ANSSI.md 10-Soutenance/Questions-reponses.md 2>&1 | grep -v -i warning
"$PY" 11-Validation/controles-exigences.py > /dev/null; echo "contrôles techniques des exigences : Controles-exigences.csv"
"$PY" 11-Validation/maj-matrice.py > /dev/null; "$PY" 11-Validation/generer-exigences-origine.py > /dev/null; "$PY" 11-Validation/generer-tableau-de-bord.py
"$PY" 11-Validation/controle-coherence.py > 11-Validation/controle-coherence-sortie.txt 2>&1 || true; grep -E "== OK|== ÉCARTS" 11-Validation/controle-coherence-sortie.txt
"$PY" 11-Validation/generer-suivi-rfi.py
"$PY" 11-Validation/generer-audit-final.py
"$PY" 11-Validation/generer-manifest.py | tail -1
"$PY" 11-Validation/verifier-manifest.py
