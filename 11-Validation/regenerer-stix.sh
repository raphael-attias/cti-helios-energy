#!/bin/bash
# Régénère toute la chaîne STIX dans l'ordre et note le hash du bundle dont dérivent validation, graphe et inventaire.
set -eu
B="$(cd "$(dirname "$0")/.." && pwd)"; PY=/Users/rapatt/Projet/cti-helios-env/.venv/bin/python
"$PY" "$B/06-STIX-Graphe/generer-bundle.py" | tail -2
"$PY" "$B/06-STIX-Graphe/valider-bundle.py" > "$B/06-STIX-Graphe/Rapport-validation-sortie.txt" 2>&1 && echo "validation : OK" || { echo "validation : ÉCHEC"; exit 1; }
"$PY" "$B/06-STIX-Graphe/generer-graphe.py" | tail -1
"$PY" "$B/06-STIX-Graphe/generer-inventaire-stix.py"
"$PY" "$B/06-STIX-Graphe/generer-liaison-stix.py" | tail -1
shasum -a 256 "$B/06-STIX-Graphe/Bundle-STIX.json" | cut -d' ' -f1 > "$B/06-STIX-Graphe/Derives-du-bundle.txt"
echo "dérivés notés pour le bundle $(cut -c1-12 "$B/06-STIX-Graphe/Derives-du-bundle.txt")"
