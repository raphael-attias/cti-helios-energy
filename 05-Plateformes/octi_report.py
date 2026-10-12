#!/usr/bin/env python3
"""Phase 2 OpenCTI (sur hiboux) : crée les 3 notes et le rapport, rattache les objets du challenge. Idempotent. Jeton jamais affiché."""
import json, sys
sys.path.insert(0, "/tmp")
from octi_lib import gql
T = json.load(open("/tmp/Textes-OpenCTI.json")); ids = json.load(open("/tmp/octi_ids.json"))
RED = "89158cb3-75d5-467a-89b3-101efcec8cc4"; LAB = [ids["challenge:helios-fictif"]]
def ex(q, v=None):
    r = gql(q, v)
    if r.get("errors"): raise RuntimeError(json.dumps(r["errors"])[:400])
    return r["data"]
F = '{mode:and,filters:[{key:"objectLabel",values:["%s"]}],filterGroups:[]}' % ids["challenge:helios-fictif"]
core = [e["node"]["id"] for e in ex('{ stixCoreObjects(filters:%s, first:500){ edges{ node{ id } } } }' % F)["stixCoreObjects"]["edges"]]
rels = [e["node"]["id"] for e in ex('{ stixCoreRelationships(filters:%s, first:500){ edges{ node{ id } } } }' % F)["stixCoreRelationships"]["edges"]]
based = [e["node"]["id"] for k in ids if k.startswith("IND-") for e in ex('query($f:[String]){ stixCoreRelationships(relationship_type:["based-on"], fromId:$f, first:20){ edges{ node{ id } } } }', {"f": [ids[k]]})["stixCoreRelationships"]["edges"]]
sg = [e["node"]["id"] for k in ids if k.startswith("IND-") for e in ex('query($f:StixRef){ stixSightingRelationships(fromId:$f, first:20){ edges{ node{ id } } } }', {"f": ids[k]})["stixSightingRelationships"]["edges"]]
aps = [e["node"]["id"] for e in ex('{ stixCoreRelationships(relationship_type:["uses"], fromId:["%s"], first:50){ edges{ node{ id to{ ... on BasicObject{ id } } } } } }' % ids["INC"])["stixCoreRelationships"]["edges"]]
aps_to = [e["node"]["to"]["id"] for e in ex('{ stixCoreRelationships(relationship_type:["uses"], fromId:["%s"], first:50){ edges{ node{ id to{ ... on BasicObject{ id } } } } } }' % ids["INC"])["stixCoreRelationships"]["edges"]]
orgs = [ids[k] for k in ("victime",) if k in ids]
allobj = sorted(set(core + rels + based + sg + aps_to + orgs))
print("objets rattachables :", len(allobj), "(objets étiquetés", len(core), "| relations", len(set(rels + based)), "| sightings", len(sg), "| techniques", len(aps_to), ")")
def note(key, abstract, content, objs):
    if key in ids: return ids[key]
    i = ex('mutation($i:NoteAddInput!){ noteAdd(input:$i){ id } }', {"i": {"attribute_abstract": abstract, "content": content, "objects": objs, "createdBy": ids["equipe"], "objectMarking": [RED], "objectLabel": LAB, "confidence": 50, "note_types": ["analysis"]}})["noteAdd"]["id"]
    ids[key] = i; return i
n1 = note("N-ALERTES", "[CHALLENGE FICTIF] N-ALERTES : registre des 12 alertes du dossier", T["n_alertes"], [ids["INC"]])
n2 = note("N-LIMITES", "[CHALLENGE FICTIF] N-LIMITES : limites et incohérences", T["n_limites"], [ids["INC"]])
n3 = note("N-ATTRIB", "[CHALLENGE FICTIF] N-ATTRIB : attribution hypothétique (inconnue)", T["n_attrib"], [ids["INC"]])
NAME = "[CHALLENGE FICTIF] Helios Energy — Investigation CTI"
ex_ = next((e["node"] for e in ex('query($s:String){ reports(search:$s, first:10){ edges{ node{ id name } } } }', {"s": "CHALLENGE FICTIF"})["reports"]["edges"] if e["node"]["name"] == NAME), None)
if "REPORT" in ids or ex_:
    ids.setdefault("REPORT", ex_["id"] if ex_ else None); print("rapport déjà présent", ids["REPORT"])
else:
    refs = [ids[k] for k in ids if k.startswith("ART-")]
    ids["REPORT"] = ex('mutation($i:ReportAddInput!){ reportAdd(input:$i){ id } }', {"i": {"name": NAME, "description": T["description"], "content": T["content"], "published": "2026-10-06T12:00:00.000Z", "report_types": ["internal-report"],
                      "confidence": 50, "createdBy": ids["equipe"], "objectMarking": [RED], "objectLabel": LAB, "externalReferences": refs, "objects": sorted(set(allobj + [n1, n2, n3] + [ids["victime"]]))}})["reportAdd"]["id"]
    print("rapport créé", ids["REPORT"])
json.dump(ids, open("/tmp/octi_ids.json", "w"), indent=1)
