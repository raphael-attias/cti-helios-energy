#!/usr/bin/env python3
"""Ingestion et relecture de l'événement MISP du challenge (exécuté SUR l'hôte MISP via Ansible, ciblé).

Sous-commandes : ingest | verify.  Clé API : fichier root 0600 /root/.challenge_misp_key (valeur jamais affichée).
Écrit uniquement dans l'organisation CHALLENGE-FICTIF (utilisateur Publisher dédié). Idempotent : si l'événement existe, ne le recrée pas.
"""
import json, os, ssl, sys, urllib.request, re

URL = "https://127.0.0.1"
KEY = open("/root/.challenge_misp_key").read().strip()
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
EV = json.load(open("/tmp/Evenement-MISP.json"))
INFO = EV["Event"]["info"]

def api(method, path, body=None):
    req = urllib.request.Request(URL + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": KEY, "Accept": "application/json", "Content-Type": "application/json", "Host": "172.16.208.253"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=120) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read())
        except Exception: return e.code, {}

def find_event():
    c, d = api("POST", "/events/restSearch", {"returnFormat": "json", "eventinfo": INFO, "limit": 5})
    r = d.get("response", []) if isinstance(d, dict) else []
    return [x["Event"] for x in r]

def me():
    c, d = api("GET", "/users/view/me"); u = d.get("User", {})
    return c, u.get("email"), u.get("org_id"), d.get("Role", {}).get("name")

def ingest():
    c, email, org, role = me()
    print(f"identité API : http={c} user={email} org_id={org} role={role}")
    assert email == "challenge-writer@helios.test" and str(org) == "2", "mauvaise identité : arrêt"
    c, v = api("GET", "/servers/getVersion"); print("version MISP :", v.get("version"), "| pymisp recommandé:", v.get("pymisp_recommended_version"))
    ex = find_event()
    if ex:
        print("événement déjà présent, pas de recréation :", [e["id"] for e in ex]); return
    c, t = api("GET", "/objectTemplates/index")
    tpl = {x["ObjectTemplate"]["name"]: x["ObjectTemplate"] for x in t} if isinstance(t, list) else {}
    print("templates disponibles :", {k: bool(v) for k, v in tpl.items() if k in ("file", "domain-ip")})
    ev = json.loads(json.dumps(EV)); ev.pop("_hors_api", None)
    for o in ev["Event"]["Object"]:
        o.pop("_ref_id", None) if False else None
        tp = tpl.get(o["name"])
        if tp: o["template_uuid"] = tp["uuid"]; o["template_version"] = tp["version"]
    c, d = api("POST", "/events/add", ev)
    print("events/add http", c)
    e = d.get("Event")
    if not e:
        print("ÉCHEC :", json.dumps(d)[:500]); return
    eid, euuid = e["id"], e["uuid"]
    print(f"événement créé id={eid} uuid={euuid} attributs={len(e.get('Attribute', []))} objets={len(e.get('Object', []))} tags={[t['Tag']['name'] if 'Tag' in t else t.get('name') for t in e.get('Tag', [])]}")
    # relation downloaded-from : BIN-002 -> URL IOC-029
    c, full = api("GET", f"/events/view/{eid}")
    fe = full["Event"]
    bin2 = next((o for o in fe["Object"] if o["name"] == "file" and any(a["value"] == "svchost_update.exe" for a in o["Attribute"])), None)
    urlv = EV["_hors_api"]["relations"][0]["vers_valeur"]
    ua = next((a for a in fe["Attribute"] if a["value"] == urlv), None)
    if bin2 and ua:
        c, r = api("POST", "/objectReferences/add", {"object_uuid": bin2["uuid"], "referenced_uuid": ua["uuid"], "referenced_type": 0, "relationship_type": "downloaded-from",
                                                      "comment": EV["_hors_api"]["relations"][0]["commentaire"]})
        print("relation downloaded-from http", c)
    # galaxies ATT&CK (techniques observées)
    for tid in EV["_hors_api"]["galaxies_attack_observees"]:
        c, g = api("POST", "/galaxy_clusters/restSearch", {"value": tid, "limit": 10})
        cl = [x["GalaxyCluster"] for x in g.get("response", [])] if isinstance(g, dict) else []
        cl = [x for x in cl if x["value"].endswith(" - " + tid)]
        if not cl:
            print(f"galaxie {tid} : cluster introuvable ({c})"); continue
        c2, r = api("POST", f"/galaxies/attachCluster/{eid}/event", {"Galaxy": {"target_id": cl[0]["id"]}})
        print(f"galaxie {tid} : {cl[0]['value']} -> attach http {c2}")
    # rapport d'événement
    rep = "# [CHALLENGE FICTIF] Helios Energy INC-2026-0302\n\nDonnées FICTIVES (plages RFC 5737, domaines .test). Aucun attribut n'est marqué to_ids.\n\n- Dossier : fourniture/ (7 fichiers), inventaires et analyses dans le dossier de mission.\n- Dates : bornes d'observation, pas début/fin certains de l'intrusion.\n- Attribution : INCONNUE (cluster non attribué) ; aucune galaxie d'acteur.\n- Limites : 3 fiches binaires, 0 échantillon ; IOC-025/026/028 de nature incertaine.\n"
    c, r = api("POST", f"/eventReports/add/{eid}", {"name": "Synthèse provisoire de l'analyse", "content": rep, "distribution": "0"})
    print("event report http", c)

def verify():
    c, email, org, role = me(); print(f"identité API : http={c} user={email} org_id={org} role={role}")
    ev = find_event()
    print("événements trouvés par info exacte :", [(e["id"], e["uuid"]) for e in ev])
    if not ev: return
    c, full = api("GET", f"/events/view/{ev[0]['id']}"); fe = full["Event"]
    print(f"distribution={fe['distribution']} published={fe['published']} analysis={fe['analysis']} threat_level={fe['threat_level_id']} org={fe['Orgc']['name']} date={fe['date']}")
    attrs = fe["Attribute"]; objs = fe["Object"]
    oattrs = [a for o in objs for a in o["Attribute"]]
    print(f"attributs top-level={len(attrs)} objets={len(objs)} attributs d'objets={len(oattrs)} total={len(attrs)+len(oattrs)}")
    from collections import Counter
    print("types top-level :", dict(Counter(a["type"] for a in attrs)))
    print("to_ids vrais :", sum(1 for a in attrs + oattrs if a["to_ids"]))
    exp = {(a["type"], a["value"]) for a in EV["Event"]["Attribute"]}
    got = {(a["type"], a["value"]) for a in attrs}
    print("attributs manquants vs manifeste :", sorted(exp - got)[:5], "| en trop :", sorted(got - exp)[:5])
    eo = {(o["name"], tuple(sorted(a["value"] for a in o["Attribute"]))) for o in EV["Event"]["Object"]}
    go = {(o["name"], tuple(sorted(a["value"] for a in o["Attribute"]))) for o in objs}
    print("objets conformes au manifeste :", eo == go)
    for o in objs:
        exp_o = next((x for x in EV["Event"]["Object"] if x["name"] == o["name"] and x.get("comment","")[:7] == o.get("comment","")[:7]), None)
        gotv = sorted((a["object_relation"], a["value"]) for a in o["Attribute"])
        print("  objet", o["name"], "->", gotv)
    print("relations d'objets :", [(r["relationship_type"], r.get("referenced_uuid")) for o in objs for r in o.get("ObjectReference", [])])
    print("tags :", [t["Tag"]["name"] if "Tag" in t else t["name"] for t in fe.get("EventTag", [])] or [t.get("name") for t in fe.get("Tag", [])])
    print("galaxies :", [(g.get("Galaxy") or g).get("name", "?") + " / " + c["value"] for g in fe.get("Galaxy", []) for c in g.get("GalaxyCluster", [])])
    print("event reports :", [(r.get("EventReport") or r).get("name") for r in fe.get("EventReport", [])])
    cnt = {}
    for a in attrs + oattrs:
        cnt[a["value"]] = cnt.get(a["value"], 0) + 1
    print("valeurs dupliquées :", [v for v, n in cnt.items() if n > 1])
    print("corrélations avec d'autres événements :", sum(len(a.get("RelatedAttribute", [])) for a in attrs + oattrs))

def fix():
    """Corrige les écarts constatés à la relecture : hostname (catégorie), size-in-bytes (catégorie), galaxies ATT&CK."""
    ev = find_event()[0]; eid = ev["id"]
    c, full = api("GET", f"/events/view/{eid}"); fe = full["Event"]
    if not any(a["value"] == "comptabilite-07" for a in fe["Attribute"]):
        a = [x for x in EV["Event"]["Attribute"] if x["value"] == "comptabilite-07"][0].copy(); a["category"] = "Network activity"
        c, r = api("POST", f"/attributes/add/{eid}", a); print("hostname (catégorie Network activity) http", c, str(r.get("Attribute", r))[:120] if c != 200 else "")
    sizes = {"facture_mars_2026.xlsm": "68242", "svchost_update.exe": "421376", "rundll32_helper.dll": "210944"}
    for o in fe["Object"]:
        if o["name"] != "file" or any(a["object_relation"] == "size-in-bytes" for a in o["Attribute"]): continue
        fn = next(a["value"] for a in o["Attribute"] if a["object_relation"] == "filename")
        c, r = api("POST", f"/objects/addAttribute/{o['id']}", {"Attribute": {"object_relation": "size-in-bytes", "type": "size-in-bytes", "category": "Other", "value": sizes[fn], "to_ids": False, "distribution": "5",
                                                                           "comment": "taille déclarée par la fiche (BIN)"}})
        print("size-in-bytes", fn, "http", c, "" if c == 200 else str(r)[:150])
    c, r = api("POST", "/galaxy_clusters/restSearch", {"galaxy_id": "48", "limit": 5000})
    allc = [x["GalaxyCluster"] for x in r.get("response", [])] if isinstance(r, dict) else []
    print("clusters ATT&CK Techniques chargés :", len(allc))
    have = {g["GalaxyCluster"][0]["value"] if g.get("GalaxyCluster") else "" for g in fe.get("Galaxy", [])}
    for tid in EV["_hors_api"]["galaxies_attack_observees"]:
        cl = [x for x in allc if x["value"].endswith(" - " + tid)]
        if not cl: print(f"galaxie {tid} : introuvable"); continue
        c2, r2 = api("POST", f"/galaxies/attachCluster/{eid}/event", {"Galaxy": {"target_id": cl[0]["id"]}})
        print(f"galaxie {tid} : {cl[0]['value']} -> http {c2}", "" if c2 == 200 else str(r2)[:150])

def diag():
    c, g = api("GET", "/galaxies/index")
    gs = [x["Galaxy"] for x in g] if isinstance(g, list) else []
    print("galaxies :", len(gs), [(x["id"], x["type"]) for x in gs if "attack" in x["type"]][:10])
    for x in gs:
        if x["type"] in ("mitre-attack-pattern",):
            c, r = api("POST", "/galaxy_clusters/restSearch", {"galaxy_id": x["id"], "limit": 3}); print("restSearch galaxy_id", c, str(r)[:300])
            c, r = api("GET", f"/galaxies/view/{x['id']}"); print("view", c, str(r)[:200])

{"ingest": ingest, "verify": verify, "diag": diag, "fix": fix}[sys.argv[1]]()
