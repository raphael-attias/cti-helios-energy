#!/usr/bin/env python3
"""Validation du bundle : (1) stix2-validator (syntaxe/bonnes pratiques), (2) analyseur stix2 (parse strict), (3) patterns stix2-patterns,
(4) contrôles de cohérence MÉTIER : références résolues, relations typées, dates, provenance, hypothèses étiquetées, absence d'acteur nommé, comptages séparés.
Venv dédié : /Users/rapatt/Projet/cti-helios-env/.venv/bin/python 06-STIX-Graphe/valider-bundle.py"""
import json, os, sys, re
from collections import Counter, defaultdict
import stix2, stix2patterns.v21.pattern as P
from stix2validator import validate_file, print_results, ValidationOptions
from antlr4 import InputStream, CommonTokenStream
from stix2patterns.validator import run_validator
G = os.path.dirname(os.path.abspath(__file__)); F = os.path.join(G, "Bundle-STIX.json")
b = json.load(open(F, encoding="utf-8")); O = b["objects"]; byid = {o["id"]: o for o in O}
print("=== 1. stix2-validator", __import__("stix2validator").__version__)
# Les schémas OASIS (dépôt cti-stix2-json-schemas, commit 9af1db41 du 2026-01-19) sont absents du paquet pip : lien symbolique schemas-2.1 dans le venv.
res = validate_file(F, ValidationOptions(version="2.1"))
print_results(res)
NERR = sum(len(x.errors) for x in res.object_results); NWARN = sum(len(x.warnings) for x in res.object_results)
print("valide :", res.is_valid, "| erreurs :", NERR, "| avertissements :", NWARN)
print("=== 2. stix2.parse (allow_custom pour x-misp-attribute)")
try:
    pb = stix2.parse(b, allow_custom=True, version="2.1"); print("parse OK :", len(pb.objects), "objets")
except Exception as e:
    print("parse ÉCHEC :", str(e)[:300]); sys.exit(1)
print("=== 3. patterns")
bad = 0
for o in O:
    if o["type"] == "indicator":
        errs = run_validator(o["pattern"], stix_version="2.1")
        print(" ", o["name"][:60], "OK" if not errs else errs); bad += bool(errs)
print("=== 4. cohérence métier")
errors = []
refs = 0
for o in O:
    for k, v in o.items():
        if k.endswith("_ref") and isinstance(v, str): refs += 1; (v in byid) or errors.append(f"référence non résolue {o['id']}.{k}")
        if k.endswith("_refs") and isinstance(v, list):
            for x in v: refs += 1; (x in byid) or errors.append(f"référence non résolue {o['id']}.{k} -> {x}")
print("références vérifiées :", refs, "| non résolues :", sum(1 for e in errors if e.startswith("référence")))
ALLOWED = {("campaign", "uses", "attack-pattern"), ("campaign", "uses", "malware"), ("campaign", "uses", "tool"), ("campaign", "uses", "infrastructure"), ("infrastructure", "consists-of", "*"), ("campaign", "targets", "identity"), ("indicator", "based-on", "*"), ("indicator", "indicates", "campaign"), ("file", "related-to", "url")}
for o in O:
    if o["type"] == "relationship":
        s, t = byid[o["source_ref"]]["type"], byid[o["target_ref"]]["type"]
        if (s, o["relationship_type"], t) not in ALLOWED and (s, o["relationship_type"], "*") not in ALLOWED:
            errors.append(f"relation non prévue {s} {o['relationship_type']} {t}")
        if not o.get("labels") and not o.get("created_by_ref") == None and o["created_by_ref"] and "confidence" not in o: errors.append("relation sans confiance " + o["id"])
for o in O:
    if "created" in o and "modified" in o and o["modified"] < o["created"]: errors.append("dates incohérentes " + o["id"])
    if o["type"] == "indicator" and not o["valid_until"] > o["valid_from"]: errors.append("validité incohérente " + o["id"])
    if o["type"] in ("campaign",) and o.get("first_seen") and o["first_seen"] > o["last_seen"]: errors.append("campagne datée à l'envers")
    if o["type"] == "observed-data" and o["last_observed"] < o["first_observed"]: errors.append("observed-data inversé " + o["id"])
    if o["type"] == "observed-data" and not ("2026-03-01" <= o["first_observed"] <= "2026-03-31"): errors.append("observed-data hors de la période de l'incident (date d'ingestion ?) " + o["id"])
    if o["type"] == "indicator" and not ("2026-03-01" <= o["valid_from"] <= "2026-03-31"): errors.append("indicator.valid_from hors période " + o["id"])
names = " ".join(str(o.get("name", "")) for o in O).lower()
for banned in ("fin7", "carbanak", "intrusion-set", "threat-actor"):
    if banned in names or any(o["type"] == banned for o in O): errors.append("acteur nommé interdit : " + banned)
print("types d'objets :", dict(Counter(o["type"] for o in O)))
ana = ("report", "grouping", "note", "campaign", "malware", "attack-pattern", "indicator", "tool", "infrastructure")
sco = ("file", "domain-name", "ipv4-addr", "url", "x509-certificate", "network-traffic", "user-account")
tech = ("marking-definition", "x-misp-attribute")
cnt = {"analytiques": sum(1 for o in O if o["type"] in ana), "observables (SCO)": sum(1 for o in O if o["type"] in sco), "observed-data (conteneurs d'observation)": sum(1 for o in O if o["type"] == "observed-data"),
       "relations": sum(1 for o in O if o["type"] == "relationship"), "identités": sum(1 for o in O if o["type"] == "identity"), "techniques (marquage, x-misp-attribute)": sum(1 for o in O if o["type"] in tech)}
print("comptage séparé :", cnt, "| total", len(O), "| somme", sum(cnt.values()))
# objets reliés : présents dans au moins une relation ou un object_refs de report/grouping/note
linked = set()
for o in O:
    if o["type"] == "relationship": linked |= {o["source_ref"], o["target_ref"]}
    if o["type"] in ("report", "grouping", "note"): linked |= set(o.get("object_refs", []))
    if o["type"] == "network-traffic": linked.add(o["dst_ref"])
conn = [o for o in O if o["id"] in linked]
print("objets reliés (relation ou conteneur) :", len(conn), "| objets analytiques reliés par une RELATION :", len({x for o in O if o['type']=='relationship' for x in (o['source_ref'], o['target_ref']) if byid[x]['type'] in ana + ('identity',)}))
hyp = Counter(l for o in O if o["type"] == "relationship" for l in o.get("labels", []))
print("statut des relations ajoutées :", dict(hyp))
if errors:
    print("ERREURS DE COHÉRENCE :"); [print(" -", e) for e in errors[:20]]; sys.exit(1)
print("COHÉRENCE MÉTIER : OK |", "patterns invalides :", bad)
