#!/usr/bin/env python3
"""Rattache les PDF produits au rapport OpenCTI (SANS déclencher les connecteurs d'import : noTriggerImport=true) et met à jour la section « Rapports produits ». Sur hiboux."""
import json, os, sys, urllib.request, uuid
sys.path.insert(0, "/tmp")
import octi_lib
from octi_lib import gql, TOKEN, URL
ids = json.load(open("/tmp/octi_ids.json")); RED = "89158cb3-75d5-467a-89b3-101efcec8cc4"
r = gql('{ __type(name:"StixDomainObjectEditMutations"){ fields { name args { name } } } }')
imp = [f for f in r["data"]["__type"]["fields"] if f["name"] == "importPush"][0]
print("importPush args :", [a["name"] for a in imp["args"]])
def push(path):
    b = uuid.uuid4().hex
    ops = {"query": "mutation($id:ID!,$file:Upload!,$m:[String]){ stixDomainObjectEdit(id:$id){ importPush(file:$file, noTriggerImport:true, fileMarkings:$m){ id name } } }", "variables": {"id": ids["REPORT"], "file": None, "m": [RED]}}
    body = b""
    def part(h, c): return f"--{b}\r\n{h}\r\n\r\n".encode() + c + b"\r\n"
    body += part('Content-Disposition: form-data; name="operations"', json.dumps(ops).encode())
    body += part('Content-Disposition: form-data; name="map"', json.dumps({"0": ["variables.file"]}).encode())
    body += part(f'Content-Disposition: form-data; name="0"; filename="{os.path.basename(path)}"\r\nContent-Type: application/pdf', open(path, "rb").read())
    body += f"--{b}--\r\n".encode()
    req = urllib.request.Request(URL, data=body, headers={"Authorization": "Bearer " + TOKEN, "Content-Type": f"multipart/form-data; boundary={b}", "apollo-require-preflight": "true"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=120).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}")
for p in sorted(os.listdir("/tmp/attach")):
    res = push("/tmp/attach/" + p); print(p, "->", json.dumps(res)[:240])
