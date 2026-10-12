#!/usr/bin/env python3
"""Ingestion ciblée OpenCTI du challenge (phase 1 : objets structurés), exécutée SUR hiboux via Ansible.

Sous-commandes : dry (lecture seule : vérifie les types et l'existant) | write (crée) | verify (relit et compte).
Garde-fous codés :
 - tout objet porte le marquage TLP:RED (connecteur IPinfo : IPINFO_MAX_TLP = TLP:AMBER, garde check_max_tlp vérifiée dans son code) ;
 - AUCUN observable Domain-Name n'est créé (connecteur Google DNS automatique, sans garde TLP) ;
 - AUCUN label du filtre du flux Jira (Incident/Case-Incident + label 5b16820b...) n'est posé ;
 - indicateurs : score 20, detection=false, valid_until passée (expirés : inactifs pour les connecteurs de détection) ; createObservables=false ;
 - idempotent : recherche avant création, aucune mise à jour d'objets existants de production, aucune suppression.
Le jeton n'est jamais affiché.
"""
import json, sys
sys.path.insert(0, "/tmp")
from octi_lib import gql

M = json.load(open("/tmp/Manifeste-OpenCTI.json"))
RED = "89158cb3-75d5-467a-89b3-101efcec8cc4"
JIRA_LABEL = "5b16820b-bf05-441c-8ecf-0a2c8f0fc8fe"
LAB = {"challenge:helios-fictif": "#e91e63", "challenge:source=dossier-pedagogique": "#2196f3", "analytic:observed": "#4caf50",
       "analytic:hypothesis": "#ff9800", "analytic:declared-unverified": "#9e9e9e", "challenge:source=rejeu-wazuh": "#9c27b0"}
ORG = {"victime": ("Helios Energy (fictif)", "[CHALLENGE FICTIF] Victime fictive de l'exercice. Statut d'opérateur d'importance vitale : énoncé du sujet, non établi par les artefacts."),
       "dossier": ("[CHALLENGE FICTIF] Dossier pédagogique (SOC Helios)", "Auteur des observations fournies par le dossier pédagogique (artefacts, alertes, fiches)."),
       "equipe": ("[CHALLENGE FICTIF] Équipe CTI", "Auteur de l'analyse. Composition de l'équipe : à confirmer.")}
SYS = {"comptabilite-07": "Poste du service comptabilité (poste d'entrée selon le dossier).",
       "srv-fichiers-02": "Serveur nommé « fichiers » : rôle déduit du nom, non documenté.",
       "dc-01": "Hôte nommé « dc » : contrôleur de domaine selon le mémo ; non vérifié."}
import os
PRIOR = json.load(open('/tmp/octi_ids.json')) if os.path.exists('/tmp/octi_ids.json') else {}
ID = {}   # id_local -> id OpenCTI
log = []

def ex(q, v=None):
    r = gql(q, v)
    if r.get("errors"):
        raise RuntimeError(json.dumps(r["errors"])[:500])
    return r["data"]

def first(q, path, v=None):
    d = ex(q, v)
    for k in path.split("."):
        d = d[k]
    es = d["edges"]
    return es[0]["node"] if es else None

def find_label(v):
    return first('query($s:String){ labels(search:$s, first:5){ edges{ node{ id value } } } }', "labels", {"s": v.split("=")[0]}) if False else \
        next((e["node"] for e in ex('query($s:String){ labels(search:$s, first:50){ edges{ node{ id value } } } }', {"s": v})["labels"]["edges"] if e["node"]["value"] == v), None)

def get_or_create(kind, key, finder, creator):
    if key in PRIOR:
        ID[key] = PRIOR[key]; log.append((kind, key, 'existant')); return PRIOR[key]
    n = finder()
    if n:
        ID[key] = n["id"]; log.append((kind, key, "existant")); return n["id"]
    if MODE == "dry":
        log.append((kind, key, "à créer")); return None
    i = creator(); ID[key] = i; log.append((kind, key, "créé")); return i

def create_labels():
    for v, c in LAB.items():
        get_or_create("label", v, lambda v=v: find_label(v),
                      lambda v=v, c=c: ex('mutation($i:LabelAddInput!){ labelAdd(input:$i){ id } }', {"i": {"value": v, "color": c}})["labelAdd"]["id"])
        assert ID.get(v) != JIRA_LABEL

def labels(*extra):
    return [ID[x] for x in ("challenge:helios-fictif",) + extra if x in ID]

def create_identities():
    for k, (name, desc) in ORG.items():
        get_or_create("organization", k, lambda name=name: next((e["node"] for e in ex('query($s:String){ organizations(search:$s, first:10){ edges{ node{ id name } } } }', {"s": name})["organizations"]["edges"] if e["node"]["name"] == name), None),
                      lambda name=name, desc=desc: ex('mutation($i:OrganizationAddInput!){ organizationAdd(input:$i){ id } }', {"i": {"name": name, "description": desc}})["organizationAdd"]["id"])
    for n, desc in SYS.items():
        get_or_create("system", n, lambda n=n: next((e["node"] for e in ex('query($s:String){ systems(search:$s, first:10){ edges{ node{ id name } } } }', {"s": n})["systems"]["edges"] if e["node"]["name"] == n), None),
                      lambda n=n, desc=desc: ex('mutation($i:SystemAddInput!){ systemAdd(input:$i){ id } }', {"i": {"name": n, "description": "[CHALLENGE FICTIF] " + desc, "createdBy": ID.get("dossier"), "objectMarking": [RED], "objectLabel": labels("challenge:source=dossier-pedagogique")}})["systemAdd"]["id"])

REFS = [("ART-001", "00_LISEZ-MOI.md"), ("ART-002", "01_fiches_analyse_binaires.md"), ("ART-003", "02_indicateurs_40.csv"), ("ART-004", "02_indicateurs_40.json"),
        ("ART-005", "03_alertes_siem_12.csv"), ("ART-006", "04_memo_technique_SOC.md"), ("ART-007", "05_journaux_bruts.log")]
SHA = {}
for l in open("/tmp/Inventaire-artefacts.csv", encoding="utf-8").read().splitlines()[1:]:
    c = l.split(","); SHA[c[2]] = c[5]
EVID = {"ALERT-002": (2, "Squid: GET https://cdn-svc-update.test/win/svchost_update.exe 200 421376"), "ALERT-004": (4, "Zeek: conn 198.51.100.24:443 duration=0.4 orig_bytes=812 (beacon)"),
        "ALERT-010": (10, "Zeek: large outbound 203.0.113.28:8080 bytes=2469135790 cleartext"), "ALERT-011": (11, "Squid: GET https://static-assets-cache.test/ 200 (failover C2)")}

def create_refs():
    for aid, fn in REFS:
        get_or_create("external-reference", aid, lambda aid=aid: next((e["node"] for e in ex('query($s:String){ externalReferences(search:$s, first:25){ edges{ node{ id external_id source_name } } } }', {"s": aid})["externalReferences"]["edges"] if e["node"]["external_id"] == aid), None),
                      lambda aid=aid, fn=fn: ex('mutation($i:ExternalReferenceAddInput!){ externalReferenceAdd(input:$i){ id } }', {"i": {"source_name": f"Dossier Helios : {fn}", "external_id": aid,
                           "description": f"Fichier source du dossier pédagogique (fourniture/{fn}). sha256 {SHA.get(fn, '?')}. Original conservé hors de la plateforme ; aucun contenu importé."}})["externalReferenceAdd"]["id"])
    for aid, (ln, raw) in EVID.items():
        key = f"EV-{aid}"
        get_or_create("external-reference", key, lambda key=key: next((e["node"] for e in ex('query($s:String){ externalReferences(search:$s, first:25){ edges{ node{ id external_id } } } }', {"s": key})["externalReferences"]["edges"] if e["node"]["external_id"] == key), None),
                      lambda key=key, aid=aid, ln=ln, raw=raw: ex('mutation($i:ExternalReferenceAddInput!){ externalReferenceAdd(input:$i){ id } }', {"i": {"source_name": f"Journal brut ligne {ln} ({aid})", "external_id": key,
                           "description": f"05_journaux_bruts.log ligne {ln} : {raw}"}})["externalReferenceAdd"]["id"])

SRC_LABEL = "challenge:source=dossier-pedagogique"
OBSERVED_IN_LOG = {"OBS-U-29", "OBS-IP-20", "OBS-IP-24", "OBS-U-X1", "OBS-IP-25"}
TYPES = {"StixFile": ("StixFile", "StixFileAddInput"), "Url": ("Url", "UrlAddInput"), "IPv4-Addr": ("IPv4Addr", "IPv4AddrAddInput"),
         "X509-Certificate": ("X509Certificate", "X509CertificateAddInput"), "User-Account": ("UserAccount", "UserAccountAddInput"), "Directory": ("Directory", "DirectoryAddInput")}

def obs_input(o):
    v = o["valeur"]; t = o["type"]
    if t == "StixFile":
        i = {}
        if "name" in v: i["name"] = v["name"]
        if "size" in v: i["size"] = v["size"]
        if "hashes" in v: i["hashes"] = [{"algorithm": a, "hash": h} for a, h in v["hashes"].items()]
        return i
    if t in ("Url", "IPv4-Addr"): return {"value": v}
    if t == "X509-Certificate": return {"hashes": [{"algorithm": a, "hash": h} for a, h in v["hashes"].items()]}
    if t == "User-Account": return {"account_login": v["account_login"]}
    if t == "Directory": return {"path": v["path"]}

def create_observables():
    for o in M["observables"]:
        assert o["type"] != "Domain-Name"
        if os.environ.get("STAGE") == "1" and o["id_local"] != "OBS-U-X1":
            continue
        arg, itype = TYPES[o["type"]]
        inp = obs_input(o)
        search = o["valeur"] if isinstance(o["valeur"], str) else (list(o["valeur"].get("hashes", {}).values()) or [o["valeur"].get("name") or o["valeur"].get("path") or o["valeur"].get("account_login")])[-1]
        status = "observé dans le journal" if o["id_local"] in OBSERVED_IN_LOG else "déclaré par le dossier, non vérifié"
        desc = f"[CHALLENGE FICTIF] {', '.join(o['iocs_sources']) or 'extrait du journal'} | {status} | {o['remarque']}"
        lab = labels(SRC_LABEL, "analytic:observed" if o["id_local"] in OBSERVED_IN_LOG else "analytic:declared-unverified")
        def finder(search=search, o=o):
            r = ex('query($s:String){ stixCyberObservables(search:$s, first:25){ edges{ node{ id entity_type observable_value } } } }', {"s": str(search)})["stixCyberObservables"]["edges"]
            return next((e["node"] for e in r if e["node"]["entity_type"] == o["type"] and str(e["node"]["observable_value"]).lower() == str(search).lower()), None)
        def creator(arg=arg, itype=itype, o=o, inp=inp, desc=desc, lab=lab):
            q = 'mutation($t:String!,$i:%s,$m:[String],$l:[String],$b:String,$d:String){ stixCyberObservableAdd(type:$t, %s:$i, objectMarking:$m, objectLabel:$l, createdBy:$b, x_opencti_description:$d){ id entity_type } }' % (itype, arg)
            return ex(q, {"t": o["type"], "i": inp, "m": [RED], "l": lab, "b": ID["dossier"], "d": desc})["stixCyberObservableAdd"]["id"]
        get_or_create("observable:" + o["type"], o["id_local"], finder, creator)

def create_indicators():
    for x in M["indicateurs"]:
        lab = labels(SRC_LABEL, "analytic:declared-unverified" if x["id_local"] in ("IND-01", "IND-02", "IND-03") else "analytic:hypothesis")
        conf = 15 if x["confiance_analyste"].startswith("faible") else 50
        mtype = {"file": "StixFile", "domain-name": "Domain-Name", "url": "Url", "ipv4-addr": "IPv4-Addr"}[x["pattern"][1:].split(":")[0]]
        name = f"[CHALLENGE FICTIF] {x['id_local']} {x['contexte_menace']}"
        def creator(x=x, lab=lab, conf=conf, mtype=mtype, name=name):
            inp = {"name": name, "description": f"[CHALLENGE FICTIF] Contexte : {x['contexte_menace']}. Sources : {', '.join(x['sources'])}. Confiance de l'analyste : {x['confiance_analyste']} (échelle de la plateforme, pas une cote Admiralty). Limites : {x['limites']}. Indicateur historique : expiré volontairement, non destiné à la détection.",
                   "pattern": x["pattern"], "pattern_type": "stix", "x_opencti_main_observable_type": mtype, "valid_from": "2026-03-02T08:30:00Z", "valid_until": "2026-04-02T00:00:00Z",
                   "confidence": conf, "x_opencti_score": 20, "x_opencti_detection": False, "createObservables": False, "createdBy": ID["dossier"], "objectMarking": [RED], "objectLabel": lab}
            if x["based_on"]:
                inp["basedOn"] = [ID[b] for b in x["based_on"]]
            return ex('mutation($i:IndicatorAddInput!){ indicatorAdd(input:$i){ id } }', {"i": inp})["indicatorAdd"]["id"]
        get_or_create("indicator", x["id_local"], lambda name=name: next((e["node"] for e in ex('query($s:String){ indicators(search:$s, first:25){ edges{ node{ id name } } } }', {"s": name[:60]})["indicators"]["edges"] if e["node"]["name"] == name), None), creator)

INC_NAME = M["noms_exacts"]["incident"]

def create_incident():
    inc = M["incident"]
    desc = ("[CHALLENGE FICTIF] Incident pédagogique INC-2026-0302 (victime fictive). Dates : bornes d'OBSERVATION du dossier (première observation 2026-03-02T08:31Z, dernière 2026-03-07T09:02Z), pas début ni fin certains de l'intrusion ; "
            "la date du mémo (2 mars) est antérieure aux faits qu'il décrit. Impacts SOUTENUS : " + " ; ".join(inc["impacts_soutenus"]) + ". Impacts NON DEMONTRES : " + " ; ".join(inc["impacts_non_demontres"]) +
            ". Attribution : INCONNUE (cluster non attribué). Alertes fournies : voir la note N-ALERTES du rapport ; aucune n'est un incident distinct.")
    get_or_create("incident", "INC", lambda: first('query($s:String){ incidents(search:$s, first:5){ edges{ node{ id name } } } }', "incidents", {"s": "Helios Energy"}) if False else
                  next((e["node"] for e in ex('query($s:String){ incidents(search:$s, first:10){ edges{ node{ id name } } } }', {"s": "CHALLENGE FICTIF"})["incidents"]["edges"] if e["node"]["name"] == INC_NAME), None),
                  lambda: ex('mutation($i:IncidentAddInput!){ incidentAdd(input:$i){ id } }', {"i": {"name": INC_NAME, "description": desc, "first_seen": "2026-03-02T08:31:00Z", "last_seen": "2026-03-07T09:02:00Z", "confidence": 50,
                             "createdBy": ID["equipe"], "objectMarking": [RED], "objectLabel": labels("analytic:observed"), "externalReferences": [ID[r[0]] for r in REFS if r[0] in ("ART-003", "ART-005", "ART-007")]}})["incidentAdd"]["id"])

def rel_exists(f, t, ty):
    r = ex('query($f:[String],$t:[String],$y:[String]){ stixCoreRelationships(fromId:$f, toId:$t, relationship_type:$y, first:1){ edges{ node{ id } } } }', {"f": [f], "t": [t], "y": [ty]})
    return bool(r["stixCoreRelationships"]["edges"])

def add_rel(key, f, t, ty, desc, conf, label_extra, refs=None):
    if not f or not t:
        log.append(("relation", key, "ignorée : extrémité absente (dry ?)")); return
    if rel_exists(f, t, ty):
        log.append(("relation", key, "existante")); return
    if MODE == "dry":
        log.append(("relation", key, "à créer")); return
    inp = {"fromId": f, "toId": t, "relationship_type": ty, "description": desc, "confidence": conf, "createdBy": ID["equipe"], "objectMarking": [RED], "objectLabel": labels(label_extra)}
    if refs: inp["externalReferences"] = refs
    ex('mutation($i:StixCoreRelationshipAddInput!){ stixCoreRelationshipAdd(input:$i){ id } }', {"i": inp}); log.append(("relation", key, "créée"))

def create_relations():
    inc = ID.get("INC")
    add_rel("INC targets victime", inc, ID.get("victime"), "targets", "[CHALLENGE FICTIF] victime fictive du dossier", 50, "analytic:observed")
    for h in SYS:
        add_rel(f"INC targets {h}", inc, ID.get(h), "targets", f"[CHALLENGE FICTIF] événements observés sur {h}", 50, "analytic:observed")
    ap = {"T1059.001": "26dd7d01-e492-4acb-89bc-3f6bd8dc2b05", "T1564.003": "1d3f37f3-66f3-462c-86bd-677f8883b4cb", "T1105": "e810fc76-1d36-43b2-bfb6-1e2698fbe027", "T1053.005": "e56e0e34-eb58-4124-a21a-e7fe096e7d55",
          "T1046": "6fc6b9cb-a9ec-43bc-92d5-b85260999595", "T1021.001": "bd98d8b8-a197-4d05-a048-15fbd78d2389", "T1055": "985f65c4-9786-47fe-8ecb-a3320bff755f", "T1070.001": "94e3f657-05fa-4eac-a258-a65a44e9312c"}
    why = {"T1059.001": "alerte 1 : powershell.exe -enc", "T1564.003": "alerte 1 : -w hidden", "T1105": "alerte 2 : GET 200 d'un exécutable", "T1053.005": "alerte 3 : création de tâche",
           "T1046": "alerte 6 : balayage 445/3389", "T1021.001": "alerte 7 : 4624 type 10", "T1055": "alerte 8 : CreateRemoteThread dans explorer.exe (technique parente ; sous-technique non démontrée)", "T1070.001": "alerte 12 : 1102 + wevtutil cl Security"}
    for t, i in ap.items():
        add_rel(f"INC uses {t}", inc, i, "uses", f"[CHALLENGE FICTIF] technique OBSERVEE : {why[t]}", 50, "analytic:observed")
    for x in M["indicateurs"]:
        add_rel(f"{x['id_local']} related-to INC", ID.get(x["id_local"]), inc, "related-to", f"[CHALLENGE FICTIF] indicateur issu d'une observation de l'incident : {x['contexte_menace']}", 15 if x["confiance_analyste"].startswith("faible") else 50, "analytic:hypothesis")

def create_observed_and_sightings():
    for od in M["observed_data"]:
        aid = od["alerte"]; key = od["id_local"]; ev = ID.get(f"EV-{aid}")
        def finder(od=od):
            r = ex('query($f:[Any!]!){ observedDatas(filters:{mode:and,filters:[{key:"objects",values:$f}],filterGroups:[]}, first:5){ edges{ node{ id first_observed } } } }', {"f": [ID.get(o) for o in od["objets"] if ID.get(o)]}) if all(ID.get(o) for o in od["objets"]) else None
            return next((e["node"] for e in r["observedDatas"]["edges"] if e["node"]["first_observed"].startswith(od["first_last"][:16])), None) if r else None
        get_or_create("observed-data", key, finder, lambda od=od, ev=ev: ex('mutation($i:ObservedDataAddInput!){ observedDataAdd(input:$i){ id } }', {"i": {"first_observed": od["first_last"], "last_observed": od["first_last"], "number_observed": 1,
                       "objects": [ID[o] for o in od["objets"]], "confidence": 50, "createdBy": ID["dossier"], "objectMarking": [RED], "objectLabel": labels(SRC_LABEL, "analytic:observed"), "externalReferences": [ev]}})["observedDataAdd"]["id"])
    hosts = {"SIG-01": "comptabilite-07", "SIG-02": "comptabilite-07", "SIG-03": "dc-01", "SIG-04": "srv-fichiers-02"}
    for s in M["sightings"]:
        f, t = ID.get(s["indicateur"]), ID.get(hosts[s["id_local"]])
        ev = ID.get("EV-" + s["preuves"][0])
        if not f or not t:
            log.append(("sighting", s["id_local"], "ignoré : extrémité absente (dry ?)")); continue
        ex_ = ex('query($f:StixRef,$t:StixRef){ stixSightingRelationships(fromId:$f, toId:$t, first:5){ edges{ node{ id first_seen } } } }', {"f": f, "t": t})["stixSightingRelationships"]["edges"]
        if ex_:
            ID[s["id_local"]] = ex_[0]["node"]["id"]; log.append(("sighting", s["id_local"], "existant")); continue
        if MODE == "dry":
            log.append(("sighting", s["id_local"], "à créer")); continue
        ID[s["id_local"]] = ex('mutation($i:StixSightingRelationshipAddInput!){ stixSightingRelationshipAdd(input:$i){ id } }', {"i": {"fromId": f, "toId": t, "first_seen": s["first_last"], "last_seen": s["first_last"], "attribute_count": 1,
                         "confidence": 15 if s["indicateur"] in ("IND-06", "IND-08") else 50, "description": f"[CHALLENGE FICTIF] {s['indicateur']} observé sur {hosts[s['id_local']]} d'après {', '.join(s['preuves'])} (alerte du dossier pédagogique, PAS un résultat de rejeu Wazuh).",
                         "createdBy": ID["dossier"], "objectMarking": [RED], "objectLabel": labels(SRC_LABEL, "analytic:observed"), "externalReferences": [ev]}})["stixSightingRelationshipAdd"]["id"]
        log.append(("sighting", s["id_local"], "créé"))

def introspect():
    for t in ("StixFileAddInput", "UrlAddInput", "IPv4AddrAddInput", "X509CertificateAddInput", "UserAccountAddInput", "DirectoryAddInput", "HashInput"):
        r = gql('{ __type(name:"%s"){ inputFields { name } } }' % t)
        print("type", t, "OK" if r["data"]["__type"] else "ABSENT")

def verify():
    from collections import Counter
    ids = json.load(open("/tmp/octi_ids.json"))
    lab = ids["challenge:helios-fictif"]
    F = '{mode:and,filters:[{key:"objectLabel",values:["%s"]}],filterGroups:[]}' % lab
    objs = ex('{ stixCoreObjects(filters:%s, first:500){ edges{ node{ id entity_type ... on StixCyberObservable{ observable_value } ... on Indicator{ name pattern valid_until x_opencti_score x_opencti_detection revoked } ... on Incident{ name first_seen last_seen } ... on ObservedData{ first_observed number_observed } objectMarking{ definition } createdBy{ name } } } } }' % F)["stixCoreObjects"]["edges"]
    nodes = [e["node"] for e in objs]
    print("OBJETS portant le label challenge :", len(nodes), dict(Counter(n["entity_type"] for n in nodes)))
    print("marquages :", dict(Counter(tuple(m["definition"] for m in n["objectMarking"]) for n in nodes)))
    print("auteurs :", dict(Counter((n.get("createdBy") or {}).get("name") for n in nodes)))
    print("Domain-Name parmi eux :", sum(1 for n in nodes if n["entity_type"] == "Domain-Name"))
    for n in nodes:
        if n["entity_type"] == "Indicator": print("  IND", n["name"][:70], "| score", n["x_opencti_score"], "| detection", n["x_opencti_detection"], "| valid_until", n["valid_until"], "| revoked", n["revoked"])
        if n["entity_type"] == "Incident": print("  INCIDENT", n["name"], n["first_seen"], n["last_seen"])
        if n["entity_type"] == "Observed-Data": print("  OBSERVED-DATA", n["first_observed"], n["number_observed"])
    rels = ex('{ stixCoreRelationships(filters:{mode:and,filters:[{key:"objectLabel",values:["%s"]}],filterGroups:[]}, first:500){ edges{ node{ id relationship_type from{ ... on BasicObject{ entity_type } } to{ ... on BasicObject{ entity_type } } } } } }' % lab)["stixCoreRelationships"]["edges"]
    print("RELATIONS portant le label :", len(rels), dict(Counter(r["node"]["relationship_type"] for r in rels)))
    based = ex('{ stixCoreRelationships(relationship_type:["based-on"], fromId:[%s], first:50){ edges{ node{ id } } } }' % ",".join('"%s"' % ids[k] for k in ids if k.startswith("IND-")))["stixCoreRelationships"]["edges"]
    print("based-on issus des indicateurs :", len(based))
    sg = []
    for k in [k for k in ids if k.startswith("IND-")]:
        sg += ex('query($f:StixRef){ stixSightingRelationships(fromId:$f, first:20){ edges{ node{ id first_seen last_seen attribute_count to{ ... on BasicObject{ entity_type } ... on System{ name } } } } } }', {"f": ids[k]})["stixSightingRelationships"]["edges"]
    print("SIGHTINGS depuis nos indicateurs :", len(sg), [(e["node"]["first_seen"][:16], e["node"]["attribute_count"], (e["node"]["to"] or {}).get("name")) for e in sg])
    # effets de bord : relations touchant nos observables qui ne sont pas les nôtres
    foreign = 0
    for n in nodes:
        if n["entity_type"] in ("IPv4-Addr", "Url", "StixFile", "X509-Certificate", "User-Account", "Directory"):
            rr = ex('query($i:[String]){ stixCoreRelationships(fromId:$i, first:20){ edges{ node{ id relationship_type objectLabel{ value } } } } }', {"i": [n["id"]]})["stixCoreRelationships"]["edges"]
            for r in rr:
                if "challenge:helios-fictif" not in [l["value"] for l in r["node"]["objectLabel"]]:
                    foreign += 1; print("  RELATION NON-CHALLENGE depuis", n["observable_value"][:40], r["node"]["relationship_type"])
    print("relations non-challenge sortant de nos observables :", foreign)
    print("Domain-Name créés avec une de nos valeurs :", len(ex('{ stixCyberObservables(filters:{mode:and,filters:[{key:"entity_type",values:["Domain-Name"]},{key:"value",values:["cdn-svc-update.test","api-telemetry-eu.test","mail-secure-login.test","static-assets-cache.test","helios-energy-portal.test","update-win-msft.test"]}],filterGroups:[]}, first:10){ edges{ node{ id } } } }')["stixCyberObservables"]["edges"]))

MODE = sys.argv[1]

def run():
    if MODE in ("dry", "write"):
        introspect()
        create_labels(); create_identities(); create_refs(); create_observables()
        if os.environ.get("STAGE") != "1":
            create_indicators(); create_incident(); create_relations(); create_observed_and_sightings()
        from collections import Counter
        print("RÉSUMÉ :", dict(Counter((k, s) for k, _, s in log)))
        for k, key, s in log:
            if s not in ("créé", "existant", "à créer", "créée", "existante"):
                print("  !", k, key, s)
        if MODE == "write": json.dump(ID, open("/tmp/octi_ids.json", "w"), indent=1)
    if MODE == "verify":
        verify()
    if MODE == "show":
        print(json.dumps(json.load(open("/tmp/octi_ids.json")), indent=1))

run()
