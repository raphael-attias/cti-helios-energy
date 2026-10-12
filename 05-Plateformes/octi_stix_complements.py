#!/usr/bin/env python3
"""Compléments STIX T13 dans OpenCTI (exécuté SUR hiboux). Modes : plan (lecture seule) | apply (écrit, idempotent) | verify (relecture).
Reprend dans OpenCTI les ajouts T13 du bundle local (06-STIX-Graphe/generer-bundle.py) :
 - 4 `Infrastructure` (téléchargement, destination de balise, destination de sortie, repli supposé), toutes NOUVELLES, étiquetées et en TLP:RED ;
 - 3 outils : `schtasks` (MITRE S0111) et `Wevtutil` (MITRE S0645) EXISTENTS déjà (entités de production : on y relie seulement notre incident, on ne les modifie pas) ;
   `powershell.exe` n'existe pas comme outil : 1 `Tool` NOUVEAU ;
 - relations : incident `uses` infrastructure (4) et outil (3) ; infrastructure `consists-of` observable existant (URL ou IPv4 ; les domaines ne sont pas des observables dans OpenCTI, garde Google DNS) ;
 - ajout des nouveaux objets et relations au rapport de la mission (conteneur).
Aucun objet existant n'est modifié ni supprimé. Aucun connecteur n'est déclenché (objets sans observable nouveau). Jeton jamais affiché."""
import json, subprocess, sys, urllib.request
URL = "http://127.0.0.1:8180/graphql"
IDS = json.loads('''__IDS__''')
RED = "89158cb3-75d5-467a-89b3-101efcec8cc4"; TEAM = IDS["equipe"]; INC = IDS["INC"]; REPORT = IDS["REPORT"]
L_MISSION, L_OBS, L_HYP, L_DECL = IDS["challenge:helios-fictif"], IDS["analytic:observed"], IDS["analytic:hypothesis"], IDS["analytic:declared-unverified"]
SRCL = IDS["challenge:source=dossier-pedagogique"]
TOKEN = subprocess.check_output(["docker", "exec", "xtm-opencti-1", "printenv", "APP__ADMIN__TOKEN"]).decode().strip()
def gql(q, v=None):
    r = urllib.request.Request(URL, data=json.dumps({"query": q, "variables": v or {}}).encode(), headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=120) as x: return json.loads(x.read())
    except urllib.error.HTTPError as e: return json.loads(e.read() or b"{}")
def ex(q, v=None):
    r = gql(q, v)
    if r.get("errors"): raise RuntimeError(json.dumps(r["errors"])[:500])
    return r["data"]
STATUS = {"observe": L_OBS, "hypothese": L_HYP, "declare": L_DECL}
INFRA = [  # clé, nom (identique au bundle), types, first_seen, statut, confiance, preuve, valeur de l'observable de composition
 ("telechargement", "[CHALLENGE FICTIF] Hébergement du téléchargement (cdn-svc-update.test)", ["hosting-malware"], "2026-03-02T08:42:00Z", "observe", 50,
  "ALERT-002, journal ligne 2 : GET 200 de svchost_update.exe, 421376 octets (IOC-013, IOC-029)", ["https://cdn-svc-update.test/win/svchost_update.exe"]),
 ("balise", "[CHALLENGE FICTIF] Destination de la connexion de balise (198.51.100.24)", ["command-and-control"], "2026-03-02T09:16:00Z", "observe", 15,
  "ALERT-004, journal ligne 4 : une connexion vers 198.51.100.24:443 ; le rôle de balise vient du texte de l'alerte, la périodicité n'est pas démontrée (IOC-020)", ["198.51.100.24"]),
 ("sortie", "[CHALLENGE FICTIF] Destination de la sortie de données (203.0.113.28)", ["exfiltration"], "2026-03-05T15:31:00Z", "observe", 50,
  "ALERT-010, journal ligne 10 : 2 469 135 790 octets vers 203.0.113.28:8080 en clair (IOC-024)", ["203.0.113.28"]),
 ("repli", "[CHALLENGE FICTIF] Repli de commande supposé (static-assets-cache.test)", ["command-and-control"], "2026-03-06T03:10:00Z", "hypothese", 15,
  "ALERT-011, journal ligne 11 : contact du domaine ; rôle de repli contredit par I-11 (IOC-016 vu dès le 3 mars)", ["https://static-assets-cache.test/"])]
TOOLS = [("powershell", "powershell.exe", None, "observe", 50, "ALERT-001, journal ligne 1 : winword.exe -> powershell.exe -enc ... -w hidden"),
         ("schtasks", "schtasks", "S0111", "declare", 15, "ALERT-003 (détail de l'alerte seulement : absent du journal brut, I-20)"),
         ("wevtutil", "Wevtutil", "S0645", "observe", 50, "ALERT-012, journal ligne 12 : 1102 audit log cleared / wevtutil cl Security")]

def find_by_name(query, root, name):
    r = ex(query, {"s": name})[root]["edges"]; return next((e["node"] for e in r if e["node"]["name"] == name), None)
def find_tool(name): return find_by_name('query($s:String){ tools(search:$s, first:10){ edges{ node{ id name createdBy{ name } } } } }', "tools", name)
def find_infra(name): return find_by_name('query($s:String){ infrastructures(search:$s, first:10){ edges{ node{ id name } } } }', "infrastructures", name)
def find_obs(val):
    r = ex('query($s:String){ stixCyberObservables(search:$s, first:10){ edges{ node{ id entity_type observable_value } } } }', {"s": val})["stixCyberObservables"]["edges"]
    return next((e["node"] for e in r if e["node"]["observable_value"] == val), None)
def rel_exists(f, t, ty):
    return bool(ex('query($f:[String],$t:[String],$y:[String]){ stixCoreRelationships(fromId:$f, toId:$t, relationship_type:$y, first:1){ edges{ node{ id } } } }', {"f": [f], "t": [t], "y": [ty]})["stixCoreRelationships"]["edges"])

def plan():
    print("## INFRASTRUCTURES")
    for k, nm, ty, fs, st, cf, ev, vals in INFRA:
        ex_ = find_infra(nm); obs = [find_obs(v) for v in vals]
        print(k, "| existe déjà :", bool(ex_), "| observables de composition :", [(o["entity_type"], o["observable_value"][:40]) if o else None for o in obs], "| statut", st, "| confiance", cf)
    print("## OUTILS")
    for k, nm, mid, st, cf, ev in TOOLS:
        t = find_tool(nm); print(k, "| outil existant :", (t["id"], t["name"], (t["createdBy"] or {}).get("name")) if t else None, "| action :", "relier l'incident (rien d'autre)" if t else "créer l'outil et relier l'incident")
    print("## RELATIONS prévues : incident uses (4 infrastructures + 3 outils) ; infrastructure consists-of observable (4) ; ajout au rapport des nouveaux objets et relations")

def apply():
    log = []
    new_objs, new_rels = [], []
    lab = lambda st: [L_MISSION, SRCL, STATUS[st]]
    for k, nm, ty, fs, st, cf, ev, vals in INFRA:
        o = find_infra(nm)
        if not o:
            o = ex('mutation($i:InfrastructureAddInput!){ infrastructureAdd(input:$i){ id name } }', {"i": {"name": nm, "description": f"Rôle réseau décrit par une alerte ({st.upper()}). Preuve : {ev}. Plage ou domaine de documentation : aucune résolution possible.",
                   "infrastructure_types": ty, "first_seen": fs, "confidence": cf, "createdBy": TEAM, "objectMarking": [RED], "objectLabel": lab(st)}})["infrastructureAdd"]; log.append(("infrastructure créée", nm[:50]))
        new_objs.append(o["id"])
        if not rel_exists(INC, o["id"], "uses"):
            r = ex('mutation($i:StixCoreRelationshipAddInput!){ stixCoreRelationshipAdd(input:$i){ id } }', {"i": {"fromId": INC, "toId": o["id"], "relationship_type": "uses", "description": f"{st.upper()} : {ev}", "confidence": cf,
                   "createdBy": TEAM, "objectMarking": [RED], "objectLabel": lab(st)}})["stixCoreRelationshipAdd"]; new_rels.append(r["id"]); log.append(("uses", k))
        for v in vals:
            ob = find_obs(v)
            if not ob: log.append(("observable absent, relation non créée", v)); continue
            if not rel_exists(o["id"], ob["id"], "consists-of"):
                r = ex('mutation($i:StixCoreRelationshipAddInput!){ stixCoreRelationshipAdd(input:$i){ id } }', {"i": {"fromId": o["id"], "toId": ob["id"], "relationship_type": "consists-of", "description": "observable déjà présent (export MISP)", "confidence": cf,
                       "createdBy": TEAM, "objectMarking": [RED], "objectLabel": lab(st)}})["stixCoreRelationshipAdd"]; new_rels.append(r["id"]); log.append(("consists-of", k))
    for k, nm, mid, st, cf, ev in TOOLS:
        t = find_tool(nm)
        if not t:
            t = ex('mutation($i:ToolAddInput!){ toolAdd(input:$i){ id name } }', {"i": {"name": nm, "description": f"Utilitaire Windows légitime dont l'emploi figure dans les artefacts ({st.upper()}). Preuve : {ev}. Aucun échantillon, aucune famille.", "confidence": cf,
                   "createdBy": TEAM, "objectMarking": [RED], "objectLabel": lab(st)}})["toolAdd"]; new_objs.append(t["id"]); log.append(("outil créé", nm))
        if not rel_exists(INC, t["id"], "uses"):
            r = ex('mutation($i:StixCoreRelationshipAddInput!){ stixCoreRelationshipAdd(input:$i){ id } }', {"i": {"fromId": INC, "toId": t["id"], "relationship_type": "uses", "description": f"{st.upper()} : {ev}", "confidence": cf,
                   "createdBy": TEAM, "objectMarking": [RED], "objectLabel": lab(st)}})["stixCoreRelationshipAdd"]; new_rels.append(r["id"]); log.append(("uses outil", nm))
        new_objs.append(t["id"])
    cur = {e["node"]["id"] for e in ex('query($id:String!){ report(id:$id){ objects(first:500){ edges{ node{ ... on BasicObject{ id } ... on BasicRelationship{ id } } } } } }', {"id": REPORT})["report"]["objects"]["edges"]}
    for i in sorted(set(new_objs + new_rels) - cur):
        ex('mutation($id:ID!,$i:StixRefRelationshipAddInput!){ stixDomainObjectEdit(id:$id){ relationAdd(input:$i){ id } } }', {"id": REPORT, "i": {"toId": i, "relationship_type": "object"}}); log.append(("ajouté au rapport", i[:8]))
    for l in log: print(*l)
    print("RESULT " + json.dumps({"objets": sorted(set(new_objs)), "relations": new_rels}))

def verify():
    out = {}
    for k, nm, ty, fs, st, cf, ev, vals in INFRA:
        o = find_infra(nm)
        if o:
            d = ex('query($id:String!){ infrastructure(id:$id){ id name infrastructure_types objectMarking{ definition } objectLabel{ value } createdBy{ name } stixCoreRelationships{ edges{ node{ relationship_type } } } } }', {"id": o["id"]})["infrastructure"]
            out[k] = {"id": d["id"], "types": d["infrastructure_types"], "marquage": [m["definition"] for m in d["objectMarking"]], "labels": [l["value"] for l in d["objectLabel"]], "relations": [e["node"]["relationship_type"] for e in d["stixCoreRelationships"]["edges"]]}
    for k, nm, mid, st, cf, ev in TOOLS:
        t = find_tool(nm); out["tool-" + k] = t["id"] if t else None
    r = ex('query($id:String!){ report(id:$id){ objects{ pageInfo{ globalCount } } } }', {"id": REPORT})["report"]["objects"]["pageInfo"]["globalCount"]
    out["rapport_objets"] = r; print("RESULT " + json.dumps(out, ensure_ascii=False))

if __name__ == "__main__": {"plan": plan, "apply": apply, "verify": verify}[sys.argv[1]]()
