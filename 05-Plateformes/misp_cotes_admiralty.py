#!/usr/bin/env python3
"""Reporte la cote Admiralty de l'ÉQUIPE dans le commentaire des attributs de l'événement MISP (exécuté SUR l'hôte MISP via Ansible).

Sous-commandes : dry | apply.  Clé API : /root/.challenge_misp_key (utilisateur Publisher dédié, id 5), valeur jamais affichée.
Ne modifie QUE le champ `comment` des attributs de l'événement du challenge (organisation CHALLENGE-FICTIF). Idempotent : un commentaire déjà à jour n'est pas réécrit.
Entrée : /tmp/Evenement-MISP.json (manifeste régénéré avec la cote de l'équipe dans chaque commentaire)."""
import json, ssl, sys, urllib.request, re

URL = "https://127.0.0.1"
KEY = open("/root/.challenge_misp_key").read().strip()
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
EV = json.load(open("/tmp/Evenement-MISP.json"))["Event"]
INFO = EV["info"]

def api(method, path, body=None):
    req = urllib.request.Request(URL + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": KEY, "Accept": "application/json", "Content-Type": "application/json", "Host": "172.16.208.253"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=120) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read())
        except Exception: return e.code, {}

c, d = api("GET", "/users/view/me"); u = d.get("User", {})
assert u.get("email") == "challenge-writer@helios.test" and str(u.get("org_id")) == "2", "mauvaise identité : arrêt"
c, d = api("POST", "/events/restSearch", {"returnFormat": "json", "eventinfo": INFO, "limit": 5})
evs = [x["Event"] for x in d.get("response", [])]
assert len(evs) == 1, f"événement attendu unique, trouvé {len(evs)}"
eid = evs[0]["id"]; c, full = api("GET", f"/events/view/{eid}"); fe = full["Event"]
print("événement", eid, "| attributs", len(fe["Attribute"]), "| objets", len(fe["Object"]))

top = {a["comment"].split(" | ")[0]: a["comment"] for a in EV["Attribute"]}
obj = {(o["name"], a["object_relation"], a["value"].lower()): a["comment"] for o in EV["Object"] for a in o["Attribute"]}
todo = []
for a in fe["Attribute"]:
    new = top.get(a["comment"].split(" | ")[0])
    if new and "cote ÉQUIPE" in new: todo.append((a["id"], a["type"], a["value"][:28], a["comment"], new))
for o in fe["Object"]:
    for a in o["Attribute"]:
        new = obj.get((o["name"], a["object_relation"], a["value"].lower()))
        if new and "cote ÉQUIPE" in new: todo.append((a["id"], a["type"], a["value"][:28], a["comment"], new))
todo = [t for t in todo if t[3] != t[4]]
print("commentaires à mettre à jour :", len(todo))
if sys.argv[1] == "dry":
    for t in todo[:3]: print(" ", t[0], t[1], t[2], "->", re.search(r"cote ÉQUIPE.*?\)", t[4]).group(0))
else:
    ok = ko = 0
    for aid, typ, val, old, new in todo:
        c, r = api("POST", f"/attributes/edit/{aid}", {"comment": new})
        if c == 200: ok += 1
        else: ko += 1; print("  ÉCHEC", aid, typ, val, "http", c, str(r)[:140])
    print(f"mis à jour : {ok} | échecs : {ko}")
    c, full = api("GET", f"/events/view/{eid}"); fe = full["Event"]
    allat = fe["Attribute"] + [a for o in fe["Object"] for a in o["Attribute"]]
    print("relecture : attributs avec cote ÉQUIPE =", sum("cote ÉQUIPE" in a["comment"] for a in allat), "/", len(allat),
          "| total", len(allat), "| to_ids vrais", sum(1 for a in allat if a["to_ids"]), "| published", fe["published"], "| distribution", fe["distribution"])
