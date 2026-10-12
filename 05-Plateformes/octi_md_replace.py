#!/usr/bin/env python3
"""Remplacement des 2 PDF joints au rapport OpenCTI par leurs versions Markdown (approuvé par l'utilisateur le 2026-10-10 : « plus un md qu'un pdf »). Exécuté SUR hiboux. Modes :
 archive : lit les fichiers actuels et les imprime en base64 (lecture seule) pour archivage local avant toute suppression ;
 apply   : supprime UNIQUEMENT nos Rapport-strategique et Rapport-tactique (.pdf ou .md) (deleteImport, nos propres pièces jointes) puis téléverse /tmp/attach/*.md (importPush, noTriggerImport, TLP:RED) ;
 verify  : relit la liste des pièces jointes (nom, taille). Aucun connecteur d'import n'est déclenché. Jeton jamais affiché."""
import base64, hashlib, json, os, subprocess, sys, urllib.request, uuid
URL = "http://127.0.0.1:8180"; G = URL + "/graphql"; REPORT = "3ec91c0f-915b-4e1d-9cd9-c1c12c79f342"; RED = "89158cb3-75d5-467a-89b3-101efcec8cc4"
TOKEN = subprocess.check_output(["docker", "exec", "xtm-opencti-1", "printenv", "APP__ADMIN__TOKEN"]).decode().strip()
def gql(q, v=None):
    r = urllib.request.Request(G, data=json.dumps({"query": q, "variables": v or {}}).encode(), headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=120) as x: return json.loads(x.read())
    except urllib.error.HTTPError as e: return json.loads(e.read() or b"{}")
def files():
    return [e["node"] for e in gql('query($id:String!){ report(id:$id){ importFiles{ edges{ node{ id name size } } } } }', {"id": REPORT})["data"]["report"]["importFiles"]["edges"]]
def archive():
    for f in files():
        r = urllib.request.Request(URL + "/storage/get/" + f["id"], headers={"Authorization": "Bearer " + TOKEN})
        b = urllib.request.urlopen(r, timeout=120).read()
        print("ARCHIVE", f["name"], len(b), hashlib.sha256(b).hexdigest(), base64.b64encode(b).decode())
def push(path):
    b = uuid.uuid4().hex
    ops = {"query": "mutation($id:ID!,$file:Upload!,$m:[String]){ stixDomainObjectEdit(id:$id){ importPush(file:$file, noTriggerImport:true, fileMarkings:$m){ id name } } }", "variables": {"id": REPORT, "file": None, "m": [RED]}}
    body = b""
    def part(h, c): return f"--{b}\r\n{h}\r\n\r\n".encode() + c + b"\r\n"
    body += part('Content-Disposition: form-data; name="operations"', json.dumps(ops).encode())
    body += part('Content-Disposition: form-data; name="map"', json.dumps({"0": ["variables.file"]}).encode())
    body += part(f'Content-Disposition: form-data; name="0"; filename="{os.path.basename(path)}"\r\nContent-Type: text/markdown', open(path, "rb").read())
    body += f"--{b}--\r\n".encode()
    req = urllib.request.Request(G, data=body, headers={"Authorization": "Bearer " + TOKEN, "Content-Type": f"multipart/form-data; boundary={b}", "apollo-require-preflight": "true"})
    try: return json.loads(urllib.request.urlopen(req, timeout=120).read())
    except urllib.error.HTTPError as e: return json.loads(e.read() or b"{}")
def apply():
    new = sorted(os.listdir("/tmp/attach")); assert new == ["Rapport-strategique.md", "Rapport-tactique.md"], new
    for f in files():
        if f["name"] not in ("Rapport-strategique.pdf", "Rapport-tactique.pdf", "Rapport-strategique.md", "Rapport-tactique.md"): print("conservé (pas à moi)", f["name"]); continue
        r = gql('mutation($n:String){ deleteImport(fileName:$n) }', {"n": f["id"]}); print("supprimé", f["name"], "ERREUR " + json.dumps(r.get("errors"))[:150] if r.get("errors") else "ok")
    for n in new:
        r = push("/tmp/attach/" + n); print("téléversé", n, json.dumps(r)[:200])
    for f in files(): print("présent", f["name"], f["size"], f["id"])
def verify():
    print("RESULT " + json.dumps(files()))
if __name__ == "__main__": {"archive": archive, "apply": apply, "verify": verify}[sys.argv[1]]()
