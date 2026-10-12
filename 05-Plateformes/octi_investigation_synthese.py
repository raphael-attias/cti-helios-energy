#!/usr/bin/env python3
"""Vue synthétique de l'enquête OpenCTI de la mission (exécuté SUR hiboux). Modes : plan (lecture seule) | apply (écrit) | verify.
Modifie UNIQUEMENT l'enquête 14c28507-... (liste des éléments suivis, description, mise en page enregistrée). Aucune entité ni relation n'est créée ou supprimée :
les éléments retirés de la vue restent dans la plateforme et dans le rapport. L'état initial est sauvegardé dans Investigation-etat-initial.json.
Format de mise en page (relevé dans le code de l'interface 6.9.21) : champ `graph_data` = base64 du JSON {identifiant: {id, x, y}}, enregistré par workspaceFieldPatch."""
import base64, json, subprocess, sys, urllib.request
URL = "http://127.0.0.1:8180/graphql"
IDS = json.loads(r'''__IDS__'''); INIT = json.loads(r'''__INIT__''')
W = "14c28507-2b09-48b8-9b36-c2dc2470d64a"
NEW = json.loads(r'''__NEW__''')    # identifiants des compléments T13 : {"infra": {...}, "tools": {...}}
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

ents = {i: tuple(v) for i, v in INIT["entites"].items()}          # id -> (type, nom) à l'état initial
def pick(t, pred=lambda n: True): return [i for i, (ty, n) in ents.items() if ty == t and pred(n)]
inc = IDS["INC"]; victim = IDS["victime"]
systems = [IDS["comptabilite-07"], IDS["srv-fichiers-02"], IDS["dc-01"]]
ap_order = ["T1059.001", "T1564.003", "T1105", "T1053.005", "T1046", "T1021.001", "T1055", "T1685.005"]
def ap_id(code):
    return next(i for i, (t, n) in ents.items() if t == "Attack-Pattern" and code in n)
techs = [ap_id(c) for c in ap_order]
tools = [NEW["tools"]["powershell"], NEW["tools"]["schtasks"], NEW["tools"]["wevtutil"]]
infra = [NEW["infra"][k] for k in ("telechargement", "balise", "sortie", "repli")]
inds = [IDS["IND-%02d" % k] for k in range(1, 9)]
obs_keys = ["OBS-F-BIN001", "OBS-F-BIN002", "OBS-F-BIN003", "OBS-U-29", "OBS-IP-20", "OBS-IP-24", "OBS-U-X1"]   # fichiers des fiches puis observables de l'infrastructure
obs = [IDS[k] for k in obs_keys]
docs = [IDS["REPORT"], IDS["N-ALERTES"], IDS["N-LIMITES"], IDS["N-ATTRIB"]]
ents.update({i: ("Infrastructure", "") for i in infra}); ents.update({i: ("Tool", "") for i in tools})
sel_entities = [inc, victim] + systems + techs + tools + infra + inds + obs + docs

# mise en page : deux bandes. Bande haute : techniques | incident | victime et actifs | indicateurs | fichiers des fiches. Bande basse : outils | infrastructure et ses observables.
# Rangée du bas : rapport et notes (limites, hypothèses, attribution). Unités du graphe ; chaque colonne a un sens, aucune arête ne passe sur un nœud du même rang.
pos = {}
def column(ids, x, y0=0, step=80, center=True):
    n = len(ids)
    for k, i in enumerate(ids): pos[i] = {"id": i, "x": x, "y": round(y0 + ((k - (n - 1) / 2) if center else k) * step)}
column(techs, 0); column([inc], 300); column([victim] + systems, 600); 
ind_order = [IDS["IND-%02d" % k] for k in (1, 2, 3, 5, 6, 7, 4, 8)]
column(ind_order, 900)
column(obs[:3], 1200, y0=-280 + 0, step=80, center=False)                       # fichiers des fiches, alignés sur IND-01 à IND-03
column(tools, 0, y0=480, step=0, center=False)
for k, i in enumerate(tools): pos[i] = {"id": i, "x": k * 200, "y": 480}
for k, i in enumerate(infra): pos[i] = {"id": i, "x": 640 + k * 240, "y": 480}
infra_obs = [IDS["OBS-U-29"], IDS["OBS-IP-20"], IDS["OBS-IP-24"], IDS["OBS-U-X1"]]
for k, i in enumerate(infra_obs): pos[i] = {"id": i, "x": 640 + k * 240, "y": 580}
for k, i in enumerate(docs): pos[i] = {"id": i, "x": k * 300, "y": 720}
COLS = []

def relations(sel):
    S = set(sel); out = {}
    def add(q, root, var):
        for e in ex(q, var)[root]["edges"]:
            n = e["node"]; f = (n["from"] or {}).get("id"); t = (n["to"] or {}).get("id")
            if f in S and t in S: out[n["id"]] = n["relationship_type"] if "relationship_type" in n else "sighting"
    for i in sel:
        add('query($f:[String]){ stixCoreRelationships(fromId:$f, first:100){ edges{ node{ id relationship_type from{ ... on BasicObject{ id } } to{ ... on BasicObject{ id } } } } } }', "stixCoreRelationships", {"f": [i]})
        add('query($f:StixRef){ stixSightingRelationships(fromId:$f, first:100){ edges{ node{ id from{ ... on BasicObject{ id } } to{ ... on BasicObject{ id } } } } } }', "stixSightingRelationships", {"f": i})
    return out

def description(excluded):
    from collections import Counter
    c = Counter(ents[i][0] for i in excluded)
    return ("VUE SYNTHÉTIQUE de l'investigation CTI INC-2026-0302 (victime fictive Helios Energy, exercice pédagogique : données fictives). CLUSTER NON ATTRIBUÉ : aucun acteur n'est représenté. "
            "Bande haute, de gauche à droite : techniques ATT&CK observées | incident | victime et actifs | indicateurs historiques expirés | fichiers des fiches. Bande basse : outils légitimes (à gauche) puis infrastructure avec ses observables ; rangée du bas : rapport et notes (limites, hypothèses, attribution). "
            "Le statut de chaque élément est porté par son étiquette (analytic:observed, analytic:declared-unverified, analytic:hypothesis) : sont des HYPOTHÈSES le lien indicateur vers incident (related-to), le rôle de repli (static-assets-cache) et le rôle de balise (une seule connexion) ; sont DÉCLARÉS les 3 fichiers des fiches (aucun échantillon fourni) et schtasks (détail d'alerte seulement). "
            f"Sélection : {len(sel_entities)} éléments choisis parce qu'ils sont reliés par au moins une relation ou portent une explication. Retirés de CETTE VUE seulement (ils restent dans la plateforme et dans le rapport 3ec91c0f) : "
            + ", ".join(f"{v} {k}" for k, v in sorted(c.items())) + " (observables sans relation avec un autre élément et données observées). Rapport de référence (graphe de connaissance complet) : /dashboard/analyses/reports/3ec91c0f-915b-4e1d-9cd9-c1c12c79f342.")

def plan():
    rel = relations(sel_entities); excluded = [i for i in ents if i not in sel_entities and i in INIT["entites"]]
    print("éléments retenus :", len(sel_entities), "| relations existantes entre eux :", len(rel), dict(__import__("collections").Counter(rel.values())))
    print("éléments retirés de la vue :", len(excluded), dict(__import__("collections").Counter(ents[i][0] for i in excluded)))
    print("positions :", len(pos), "| x de", min(p["x"] for p in pos.values()), "à", max(p["x"] for p in pos.values()), "| y de", min(p["y"] for p in pos.values()), "à", max(p["y"] for p in pos.values()))
    print("DESCRIPTION :", description(excluded))

def apply():
    rel = relations(sel_entities); excluded = [i for i in ents if i not in sel_entities and i in INIT["entites"]]
    ids_all = sel_entities + sorted(rel)
    desc = description(excluded)
    ex('mutation($id:ID!,$i:[EditInput!]!){ workspaceFieldPatch(id:$id, input:$i){ id } }', {"id": W, "i": [
        {"key": "investigated_entities_ids", "value": ids_all}, {"key": "description", "value": [desc]},
        {"key": "graph_data", "value": [base64.b64encode(json.dumps(pos, separators=(",", ":")).encode()).decode()]}]})
    print("enregistré :", len(ids_all), "identifiants (", len(sel_entities), "éléments +", len(rel), "relations ), positions :", len(pos))

def verify():
    w = ex('query($id:String!){ workspace(id:$id){ id name description tags investigated_entities_ids graph_data updated_at objects{ pageInfo{ globalCount } } } }', {"id": W})["workspace"]
    g = json.loads(base64.b64decode(w["graph_data"])) if w["graph_data"] else {}
    print("RESULT " + json.dumps({"id": w["id"], "ids": len(w["investigated_entities_ids"] or []), "objets": w["objects"]["pageInfo"]["globalCount"], "positions": len(g), "maj": w["updated_at"], "description_longueur": len(w["description"] or ""), "tags": w["tags"]}))

if __name__ == "__main__": {"plan": plan, "apply": apply, "verify": verify}[sys.argv[1]]()
