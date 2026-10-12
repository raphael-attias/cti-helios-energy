#!/usr/bin/env python3
"""P1 (approuvée le 2026-10-07 par l'utilisateur) : ajoute l'étiquette challenge:helios-fictif et le marquage TLP:RED aux 3 organisations de support
(Équipe CTI, Dossier pédagogique, Helios Energy fictif). Modes : plan (lecture) | apply (3 x 2 relations d'ajout, idempotent) | verify. Exécuté SUR hiboux ; jeton jamais affiché."""
import json, subprocess, sys, urllib.request
URL = "http://127.0.0.1:8180/graphql"
IDS = json.loads('''__IDS__''')
RED = "89158cb3-75d5-467a-89b3-101efcec8cc4"; LAB = IDS["challenge:helios-fictif"]
ORGS = {"equipe": IDS["equipe"], "dossier": IDS["dossier"], "victime": IDS["victime"]}
TOKEN = subprocess.check_output(["docker", "exec", "xtm-opencti-1", "printenv", "APP__ADMIN__TOKEN"]).decode().strip()
def gql(q, v=None):
    r = urllib.request.Request(URL, data=json.dumps({"query": q, "variables": v or {}}).encode(), headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=120) as x: return json.loads(x.read())
    except urllib.error.HTTPError as e: return json.loads(e.read() or b"{}")
def state(i):
    d = gql('query($id:String!){ organization(id:$id){ id name entity_type objectLabel{ id value } objectMarking{ id definition } } }', {"id": i}); return d.get("data", {}).get("organization") or d
def plan():
    for k, i in ORGS.items(): print(k, json.dumps(state(i), ensure_ascii=False))
def apply():
    for k, i in ORGS.items():
        s = state(i); labs = [x["id"] for x in s["objectLabel"]]; mks = [x["id"] for x in s["objectMarking"]]
        for typ, to, have in (("object-label", LAB, labs), ("object-marking", RED, mks)):
            if to in have: print(k, typ, "déjà présent"); continue
            r = gql('mutation($id:ID!,$i:StixRefRelationshipAddInput!){ stixDomainObjectEdit(id:$id){ relationAdd(input:$i){ id } } }', {"id": i, "i": {"toId": to, "relationship_type": typ}})
            print(k, typ, "ERREUR " + json.dumps(r.get("errors"))[:200] if r.get("errors") else "ajouté")
def verify():
    for k, i in ORGS.items(): print(k, json.dumps(state(i), ensure_ascii=False))
if __name__ == "__main__": {"plan": plan, "apply": apply, "verify": verify}[sys.argv[1]]()
