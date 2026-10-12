#!/usr/bin/env python3
"""Vérifie les techniques de Matrice-ATTACK.csv contre les bundles STIX OFFICIELS de MITRE (dépôt mitre-attack/attack-stix-data),
version historique v18.1 (en vigueur lors de l'incident de mars 2026) et versions actuelles v19.0 et v19.2.
Les bundles (50 Mo chacun) ne sont pas copiés dans le dossier : leurs sha256 sont notés dans la sortie.
Usage : python3 04-Analyse/verifier-attack.py <dossier contenant attack-18.1.json attack-19.0.json attack-19.2.json>
Sortie : 04-Analyse/Correspondance-ATTACK-v18-v19.csv"""
import csv, hashlib, json, os, sys
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = sys.argv[1]
VERS = ["18.1", "19.0", "19.2"]
def load(v):
    f = os.path.join(D, f"attack-{v}.json"); raw = open(f, "rb").read()
    objs = json.loads(raw)["objects"]
    ap = {}; byid = {o["id"]: o for o in objs}
    for o in objs:
        if o["type"] == "attack-pattern":
            for r in o.get("external_references", []):
                if r.get("source_name") == "mitre-attack": ap[r["external_id"]] = o
    revby = {}
    for o in objs:
        if o["type"] == "relationship" and o["relationship_type"] == "revoked-by": revby[o["source_ref"]] = byid.get(o["target_ref"])
    return hashlib.sha256(raw).hexdigest(), ap, revby
data = {v: load(v) for v in VERS}
def info(v, tid):
    ap, revby = data[v][1], data[v][2]
    o = ap.get(tid)
    if not o: return ("absente", "", "")
    st = "révoquée" if o.get("revoked") else "dépréciée" if o.get("x_mitre_deprecated") else "active"
    new = ""
    if o.get("revoked") and o["id"] in revby and revby[o["id"]]:
        n = revby[o["id"]]; new = next(r["external_id"] for r in n["external_references"] if r["source_name"] == "mitre-attack") + " " + n["name"]
    return (st, o["name"], new)
def tactics(v, tid):
    o = data[v][1].get(tid); return ",".join(p["phase_name"] for p in o.get("kill_chain_phases", [])) if o else ""
rows = []
for r in csv.DictReader(open(os.path.join(B, "04-Analyse", "Matrice-ATTACK.csv"), encoding="utf-8")):
    tid = r["technique_id"]; nom_dossier = r["nom_officiel"].split(": ")[-1]
    out = {"technique_id": tid, "nom_dans_le_dossier": r["nom_officiel"]}
    for v in VERS:
        st, nm, new = info(v, tid); out[f"v{v}_statut"] = st; out[f"v{v}_nom"] = nm; out[f"v{v}_remplacee_par"] = new; out[f"v{v}_tactiques"] = tactics(v, tid)
    out["nom_dossier_conforme_a_v19.2"] = "oui" if out["v19.2_statut"] == "active" and nom_dossier.lower() in (out["v19.2_nom"].lower(), ) else ("oui (nom court)" if out["v19.2_statut"] == "active" and out["v19.2_nom"].lower() in r["nom_officiel"].lower() else "non")
    out["identifiant_a_citer_v19.2"] = tid if out["v19.2_statut"] == "active" else (out["v19.2_remplacee_par"].split(" ")[0] if out["v19.2_remplacee_par"] else "")
    out["identifiant_a_citer_v18.1"] = tid if out["v18.1_statut"] == "active" else ""
    rows.append(out)
# technique renumérotée absente du dossier mais attendue : T1070.001 (v18.1) -> T1685.005 (v19)
for old in ("T1070.001",):
    if old not in {x["technique_id"] for x in rows}:
        out = {"technique_id": old, "nom_dans_le_dossier": "(non retenue : remplacée par T1685.005)"}
        for v in VERS:
            st, nm, new = info(v, old); out[f"v{v}_statut"] = st; out[f"v{v}_nom"] = nm; out[f"v{v}_remplacee_par"] = new; out[f"v{v}_tactiques"] = tactics(v, old)
        out["nom_dossier_conforme_a_v19.2"] = "n/a"; out["identifiant_a_citer_v19.2"] = out["v19.2_remplacee_par"].split(" ")[0]; out["identifiant_a_citer_v18.1"] = old
        rows.append(out)
with open(os.path.join(B, "04-Analyse", "Correspondance-ATTACK-v18-v19.csv"), "w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
print("sha256 des bundles :", {v: data[v][0] for v in VERS})
for x in rows: print(x["technique_id"], "| v18.1", x["v18.1_statut"], "| v19.0", x["v19.0_statut"], "| v19.2", x["v19.2_statut"], x["v19.2_remplacee_par"], "| nom v19.2 :", x["v19.2_nom"], "| conforme :", x["nom_dossier_conforme_a_v19.2"])
