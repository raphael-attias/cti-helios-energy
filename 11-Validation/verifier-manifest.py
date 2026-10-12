#!/usr/bin/env python3
"""Recalcule les hashes de Manifest-livrables.csv et signale tout écart ; vérifie que graphe et inventaire STIX dérivent du bundle courant (Derives-du-bundle.txt)."""
import csv, hashlib, os, sys
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); bad = []; n = 0
for r in csv.DictReader(open(os.path.join(B, "11-Validation", "Manifest-livrables.csv"), encoding="utf-8")):
    p = os.path.join(B, r["chemin_relatif"]); n += 1
    if not os.path.exists(p): bad.append(("absent", r["chemin_relatif"])); continue
    if hashlib.sha256(open(p, "rb").read()).hexdigest() != r["sha256"]: bad.append(("hash", r["chemin_relatif"]))
on_disk = sum(len(fs) for _, ds, fs in os.walk(B))
print(f"manifeste : {n} lignes vérifiées, {len(bad)} écart(s) ; fichiers sur disque : {on_disk} (le manifeste n'inclut pas son propre fichier)")
for b in bad[:10]: print("  ECART", b)
d = os.path.join(B, "06-STIX-Graphe", "Derives-du-bundle.txt")
cur = hashlib.sha256(open(os.path.join(B, "06-STIX-Graphe", "Bundle-STIX.json"), "rb").read()).hexdigest()
src = open(d).read().split()[0] if os.path.exists(d) else None
print("graphe, validation et inventaire dérivés du bundle courant :", "OUI" if src == cur else f"NON (bundle {cur[:12]}, dérivés {str(src)[:12]})")
sys.exit(1 if bad or src != cur else 0)
