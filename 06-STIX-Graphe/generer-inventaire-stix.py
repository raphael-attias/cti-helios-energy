#!/usr/bin/env python3
"""Inventaire des 133 objets du bundle (Inventaire-objets-STIX.csv), régénéré depuis Bundle-STIX.json.
Venv : /Users/rapatt/Projet/cti-helios-env/.venv/bin/python 06-STIX-Graphe/generer-inventaire-stix.py"""
import json, csv, os
G = os.path.dirname(os.path.abspath(__file__))
b = json.load(open(os.path.join(G, "Bundle-STIX.json"), encoding="utf-8")); O = b["objects"]; by = {o["id"]: o for o in O}
exp_ids = {o["id"] for o in json.load(open(os.path.join(G, "Export-MISP-brut.json"), encoding="utf-8"))["objects"]}
SCO = {"file", "domain-name", "ipv4-addr", "url", "x509-certificate", "network-traffic", "user-account"}
ANA = {"report", "grouping", "note", "campaign", "malware", "attack-pattern", "indicator"}
def cat(t): return "observable (SCO)" if t in SCO else "analytique" if t in ANA else "observed-data" if t == "observed-data" else "relation" if t == "relationship" else "identité" if t == "identity" else "technique"
def val(o):
    t = o["type"]
    if t == "relationship": return f"{o['relationship_type']} : {by[o['source_ref']]['type']} -> {by[o['target_ref']]['type']}"
    for k in ("name", "value", "hashes", "user_id", "abstract"):
        if k in o: return str(o[k])
    return ""
rows = []
for o in O:
    t = o["type"]
    local = (t == "user-account") or (t not in SCO and o["id"] not in exp_ids)
    rows.append([o["id"], t, cat(t), val(o), "enrichissement local documenté" if local else "export MISP réel (événement 6)",
                 o.get("created_by_ref", "(SCO : provenance par observed-data/report)" if t in SCO else ""),
                 (o.get("labels") or [""])[0] if t in ANA | {"relationship"} and local else "", o.get("confidence", "")])
with open(os.path.join(G, "Inventaire-objets-STIX.csv"), "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f); w.writerow(["id", "type", "categorie", "nom_ou_valeur", "provenance", "created_by_ref", "statut_analytique", "confiance"]); w.writerows(rows)
print(len(rows), "lignes")
