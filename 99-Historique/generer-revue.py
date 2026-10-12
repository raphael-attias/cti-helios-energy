#!/usr/bin/env python3
"""Génère 11-Validation/Revue-cloture.md depuis le gabarit et la matrice (tableau des 24 exigences initialement « À CONTRÔLER »)."""
import csv, os
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
M = {r["id"]: r for r in csv.DictReader(open(os.path.join(B, "00-Pilotage", "Matrice-exigences.csv"), encoding="utf-8"))}
IDS = ["REQ-05", "REQ-06", "REQ-07", "REQ-08", "REQ-09", "REQ-10", "REQ-11", "REQ-12", "REQ-15", "REQ-17", "REQ-18", "REQ-19", "REQ-20", "REQ-21", "REQ-25", "REQ-26", "REQ-27", "REQ-28", "REQ-29", "REQ-30", "REQ-31", "REQ-32", "REQ-34", "REQ-35"]
t = "| Exigence | Statut | Contrôles techniques | Limite | Relecture humaine utile |\n|---|---|---|---|---|\n"
for i in IDS:
    r = M[i]; t += f"| {i} {r['exigence'][:60]} | {r['statut']} | {r['controles_techniques']} | {r['manque_ou_limite'][:150]} | {r['relecture_humaine_necessaire']} |\n"
off = [r for k, r in M.items() if k.startswith("REQ-")]
nv = sum(1 for r in off if r["statut"] == "VALIDÉ")
g = open(os.path.join(B, "11-Validation", "revue-cloture.gabarit.md"), encoding="utf-8").read()
C = list(csv.DictReader(open(os.path.join(B, "11-Validation", "Controles-exigences.csv"), encoding="utf-8")))
g = g.replace("@@NCTL@@", str(len(C))).replace("@@NKO@@", str(sum(1 for c in C if c["resultat"] == "KO")))
g = g.replace("@@REQ_TABLE@@", t).replace("@@NV@@", str(nv)).replace("@@S36@@", M["REQ-36"]["statut"] + (" (dépôt créé et vérifié)" if M["REQ-36"]["statut"] == "VALIDÉ" else " (à créer par l'utilisateur)"))
open(os.path.join(B, "11-Validation", "Revue-cloture.md"), "w", encoding="utf-8").write(g)
print("Revue-cloture.md : %d validées sur %d" % (nv, len(off)))
