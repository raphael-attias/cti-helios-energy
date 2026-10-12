#!/var/ossec/framework/python/bin/python3
"""Rejoue des événements via l'API Wazuh (POST /events) DEPUIS le conteneur manager. Identifiants lus dans l'environnement du conteneur, jamais affichés.
Usage : wz_api_replay.py <fichier.tsv> <debut> <fin>  (indices 0-based, fin exclue)"""
import base64, json, os, ssl, sys, time, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
auth = base64.b64encode(f"{os.environ['API_USERNAME']}:{os.environ['API_PASSWORD']}".encode()).decode()
def call(method, path, body=None, token=None):
    h = {"Content-Type": "application/json"}
    h["Authorization"] = ("Bearer " + token) if token else ("Basic " + auth)
    r = urllib.request.Request("https://localhost:55000" + path, method=method, data=None if body is None else json.dumps(body).encode(), headers=h)
    with urllib.request.urlopen(r, context=ctx, timeout=60) as x: return x.read().decode()
tok = call("POST", "/security/user/authenticate?raw=true")
rows = [l.rstrip("\n").split("\t", 3) for l in open(sys.argv[1], encoding="utf-8")]
sel = rows[int(sys.argv[2]):int(sys.argv[3])]
print("heure d'envoi (UTC) :", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "| événements envoyés :", len(sel))
for i in range(0, len(sel), 20):
    r = call("POST", "/events", {"events": [x[3] for x in sel[i:i + 20]]}, tok)
    print("batch", i // 20, "->", json.loads(r).get("data", {}).get("total_affected_items", "?"), "pris en compte")
print("ids :", [x[0] for x in sel])
