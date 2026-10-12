#!/usr/bin/env python3
"""Construit Bundle-STIX.json à partir de l'EXPORT MISP RÉEL (Export-MISP-brut.json, événement 6 de l'instance MISP, STIX 2.1 produit par MISP) + enrichissements analytiques locaux.

Transformations documentées (voir Rapport-validation-STIX.md) :
 T1  export MISP brut conservé intact dans Export-MISP-brut.json ; le bundle final en est dérivé ;
 T2  observed-data : last_observed corrigé = first_observed (MISP met la date de création de l'export quand l'attribut n'a pas de last_seen), number_observed = 1 ;
 T3  ajout d'objets ANALYTIQUES absents de l'export (galaxies exclues : l'export MISP échoue avec galaxies, erreur PyMISP « distribution ... default galaxy cluster ») :
     attack-pattern (8 techniques OBSERVEES), indicator (8), malware (3, déclarés par les fiches), campaign (cluster NON ATTRIBUE), identities victime/systèmes/équipe, notes, report ;
 T4  relations ajoutées avec statut (labels observe / hypothese / declare) et confiance ;
 T5  aucune relation vers un acteur, groupe ou famille nommée ;
 T6  les 7 objets personnalisés `x-misp-attribute` (types MISP sans équivalent STIX : text, size-in-bytes) sont RETIRES du bundle final (non conformes au schéma standard,
     le validateur ne sait pas les valider) ; leur contenu est converti : size-in-bytes -> propriété `size` des `file` des fiches ; compte -> SCO `user-account` ;
     nom de tâche, valeur de registre tronquée et hôte victime -> note STIX dédiée. Ils restent dans Export-MISP-brut.json.
Révision de clôture 2026-10-06 :
 T8  identifiants des SCO recalculés de façon déterministe (UUIDv5, espace de noms STIX, propriétés contributrices) avec la bibliothèque stix2 ; toutes les références sont réécrites ;
 T9  la relation `downloaded-from` entre deux observed-data (exportée par MISP) est reportée sur les SCO sous-jacents (fichier -> URL) avec le type `related-to` (le type exporté n'a pas de sémantique STIX pour cette paire) ;
 T10 valid_from de chaque indicateur = horodatage de la PREMIÈRE alerte qui le porte (et non une date uniforme).

 T13 (2026-10-07) ajout de 3 `tool` (powershell.exe, wevtutil.exe, schtasks.exe) et de 4 `infrastructure` (téléchargement, destination de balise, destination de sortie, repli) prouvés par le journal brut ou les alertes, reliés à la campagne (`uses`) et aux observables existants (`consists-of`) ;
 T12 `observed-data` issus d'objets MISP (file, domain-ip) : first_observed = date d'ingestion exportée par MISP, remplacée par la plus ancienne « première vue » des IoC de l'objet ;
 T14 (2026-10-10) chaque objet porte sa source et sa date de collecte : les SCO (adresses, domaines, URL, fichiers, certificats, trafic, compte), qui n'ont ni `created` ni `created_by_ref` en STIX 2.1,
     reçoivent `x_helios_source` (fichier, IoC et ligne du dossier), `x_helios_collected_at` (date d'acquisition de l'inventaire) et `x_helios_admiralty` (cote de l'équipe) ; la relation exportée par MISP sans auteur reçoit `created_by_ref` ;
 T11 `indicator based-on` pointe vers l'observed-data qui contient l'observable (cible suggérée par la spécification) quand il existe, sinon vers le SCO.
Exécuter avec le venv dédié : /Users/rapatt/Projet/cti-helios-env/.venv/bin/python 06-STIX-Graphe/generer-bundle.py"""
import json, os, uuid, copy
import stix2
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
G = os.path.join(BASE, "06-STIX-Graphe")
exp = json.load(open(os.path.join(G, "Export-MISP-brut.json"), encoding="utf-8"))
objs = copy.deepcopy(exp["objects"])
NS = uuid.UUID("9b2f6a58-3c1d-4e7a-8f10-5d2c6b7a9e44")
U = lambda t, k: f"{t}--{uuid.uuid5(NS, k)}"
NOW = "2026-10-06T12:00:00.000Z"
TLP = next(o["id"] for o in objs if o["type"] == "marking-definition")
MISP_ORG = next(o["id"] for o in objs if o["type"] == "identity")

# T6 : retrait des x-misp-attribute avec conversion
XM = [o for o in objs if o["type"] == "x-misp-attribute"]
SIZES = {"2d10d13c3f3a045dc12a48e0a484018c053d0e83c607f2796fc9b8307c0d66e5": 68242, "cdf03e90d85977619f7881a13f59a275812dbf0e4ae29874493728b0ef78ebc9": 421376, "f4109cd2860816d568c5581edf8ed5df28d35471fa8ff849e9ee2451b69135f0": 210944}
for o in objs:
    if o["type"] == "file" and o.get("hashes", {}).get("SHA-256") in SIZES: o["size"] = SIZES[o["hashes"]["SHA-256"]]
XM_IDS = {o["id"] for o in XM}
objs = [o for o in objs if o["type"] != "x-misp-attribute"]
for o in objs:
    if "object_refs" in o: o["object_refs"] = [r for r in o["object_refs"] if r not in XM_IDS]
UA = {"type": "user-account", "spec_version": "2.1", "id": "user-account--" + str(uuid.uuid5(NS, "svc-backup-temp")), "user_id": "svc-backup-temp", "account_login": "svc-backup-temp"}
objs.append(UA)
ctx_vals = {o.get("x_misp_value"): o.get("x_misp_comment", "")[:90] for o in XM if o.get("x_misp_type") == "text"}

# T2 : correction des observed-data
fixed = 0
for o in objs:
    if o["type"] == "observed-data":
        o["last_observed"] = o["first_observed"]; o["number_observed"] = 1; fixed += 1

# T12 : observed-data issus d'OBJETS MISP (file, domain-ip) : MISP n'a pas de first_seen sur les attributs d'objets et exporte la date d'INGESTION
# (2026-10-06) comme first_observed. Correction : plus ancienne « première vue » des lignes du CSV d'IoC portant les valeurs de l'objet.
import csv as _csv
_IOC = list(_csv.DictReader(open(os.path.join(BASE, "fourniture", "02_indicateurs_40.csv"), encoding="utf-8")))
_byval = {r["valeur"].strip().lower(): r["premiere_vue"] for r in _IOC}
_sco = {o["id"]: o for o in objs}
T12 = 0
for o in objs:
    if o["type"] == "observed-data" and o["first_observed"] >= "2026-10-01":
        vals = []
        for ref in o["object_refs"]:
            c = _sco[ref]; vals += [c.get("value")] + list((c.get("hashes") or {}).values())
        dates = [_byval[v.lower()] for v in vals if v and v.lower() in _byval]
        assert dates, ("aucune première vue trouvée", o["id"])
        o["first_observed"] = min(dates); T12 += 1

# T8 : identifiants déterministes des SCO (UUIDv5 sur les propriétés contributrices, via stix2)
SCO_TYPES = {"file", "domain-name", "ipv4-addr", "url", "x509-certificate", "network-traffic", "user-account"}
OLD2NEW = {}
for o in sorted([o for o in objs if o["type"] in SCO_TYPES], key=lambda o: o["type"] == "network-traffic"):
    props = {k: v for k, v in o.items() if k not in ("id", "type", "spec_version")}
    for k in ("src_ref", "dst_ref"):
        if k in props: props[k] = OLD2NEW.get(props[k], props[k])
    OLD2NEW[o["id"]] = stix2.v21.OBJ_MAP_OBSERVABLE[o["type"]](allow_custom=True, **props).id
assert len(set(OLD2NEW.values())) == len(OLD2NEW), "collision d'identifiants SCO"
_txt = json.dumps(objs, ensure_ascii=False)
for old, new_id in OLD2NEW.items(): _txt = _txt.replace(f'"{old}"', f'"{new_id}"')
objs = json.loads(_txt)
UA = next(o for o in objs if o["type"] == "user-account")
# T9 : relation downloaded-from observed-data -> observed-data, reportée sur les SCO sous-jacents
_od = {o["id"]: o for o in objs if o["type"] == "observed-data"}
for o in objs:
    if o["type"] == "relationship" and o.get("relationship_type") == "downloaded-from" and o["source_ref"] in _od and o["target_ref"] in _od:
        o["source_ref"] = _od[o["source_ref"]]["object_refs"][0]; o["target_ref"] = _od[o["target_ref"]]["object_refs"][0]
        o["relationship_type"] = "related-to"; o["description"] = "MISP : référence « downloaded-from » de l'objet file vers l'URL (déclaré par la fiche, non vérifié)"

def sdo(t, key, **kw):
    o = {"type": t, "spec_version": "2.1", "id": U(t, key), "created": NOW, "modified": NOW}
    o.update(kw); return o

TEAM = sdo("identity", "equipe-cti", name="[CHALLENGE FICTIF] Équipe CTI", identity_class="organization", description="Auteur de l'analyse. Composition non communiquée.")
VICT = sdo("identity", "victime", name="Helios Energy (fictif)", identity_class="organization", description="[CHALLENGE FICTIF] Victime fictive. Statut d'opérateur d'importance vitale : énoncé du sujet, non établi par les artefacts.", created_by_ref=TEAM["id"], object_marking_refs=[TLP])
SYS = {n: sdo("identity", "sys-" + n, name=n, identity_class="system", description=d, created_by_ref=TEAM["id"], object_marking_refs=[TLP])
       for n, d in (("comptabilite-07", "Poste d'entrée selon le dossier."), ("srv-fichiers-02", "Nom évoquant un serveur de fichiers (rôle non documenté)."), ("dc-01", "Contrôleur de domaine selon le mémo (non vérifié)."))}
new = [TEAM, VICT] + list(SYS.values())

def er(desc, ext_id=None):
    e = {"source_name": "Dossier Helios (challenge fictif)", "description": desc}
    if ext_id: e["external_id"] = ext_id
    return e

def mitre(tid, name, url, desc):
    return sdo("attack-pattern", tid, name=name, description=desc, created_by_ref=TEAM["id"], object_marking_refs=[TLP], labels=["observe"],
               external_references=[{"source_name": "mitre-attack", "external_id": tid, "url": url}, er("technique OBSERVEE, preuve : " + desc)])
AP = {}
for tid, nm, d in (("T1059.001", "PowerShell", "alerte 1, journal ligne 1 : powershell.exe -enc"), ("T1564.003", "Hidden Window", "alerte 1 : -w hidden"), ("T1105", "Ingress Tool Transfer", "alerte 2 : GET 200 d'un exécutable"),
                   ("T1053.005", "Scheduled Task", "alerte 3 : création de tâche"), ("T1046", "Network Service Discovery", "alerte 6 : balayage 445 et 3389"), ("T1021.001", "Remote Desktop Protocol", "alerte 7 : 4624 type 10"),
                   ("T1055", "Process Injection", "alerte 8 : CreateRemoteThread dans explorer.exe (sous-technique non démontrée)"),
                   ("T1685.005", "Clear Windows Event Logs", "alerte 12 : 1102 + wevtutil cl Security ; ancien identifiant T1070.001 (ATT&CK <= v18)")):
    AP[tid] = mitre(tid, nm, "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/", d)
new += list(AP.values())

CAMP = sdo("campaign", "cluster-non-attribue", name="[CHALLENGE FICTIF] Cluster non attribué INC-2026-0302",
           description="Regroupement d'activités observées dans le dossier. NON ATTRIBUE : aucun acteur, groupe ou famille nommée n'est démontré. Dates = bornes d'OBSERVATION, pas début ni fin certains.",
           first_seen="2026-03-02T08:31:00Z", last_seen="2026-03-07T09:02:00Z", created_by_ref=TEAM["id"], object_marking_refs=[TLP], labels=["non-attribue"], confidence=50,
           external_references=[er("alertes 1 à 12, journal brut lignes 1 à 12", "ALERT-001..012")])
MAL = {}
for n, nm, mt, d in (("BIN-001", "facture_mars_2026.xlsm", ["dropper"], "Verdict de la fiche : dropper. Échantillon non fourni."), ("BIN-002", "svchost_update.exe", ["backdoor"], "Verdict de la fiche : balise de commande et contrôle. Échantillon non fourni."),
                     ("BIN-003", "rundll32_helper.dll", ["unknown"], "Verdict de la fiche : outil de collecte d'identifiants (outil générique selon la fiche). Échantillon non fourni.")):
    MAL[n] = sdo("malware", n, name=f"{nm} ({n})", is_family=False, malware_types=mt, description="DECLARE par la fiche, non vérifié. " + d, created_by_ref=TEAM["id"], object_marking_refs=[TLP], labels=["declare"], confidence=15,
                 external_references=[er("fiche 01_fiches_analyse_binaires.md : " + n, n)])
new += [CAMP] + list(MAL.values())

# lien indicateurs -> observables de l'export
def find(t, **kv):
    for o in objs:
        if o["type"] == t and all(o.get(k) == v or (isinstance(o.get(k), dict) and o[k].get("SHA-256") == v) for k, v in kv.items()): return o
    raise KeyError((t, kv))
def sco_file(sha): return next(o for o in objs if o["type"] == "file" and o.get("hashes", {}).get("SHA-256") == sha)
IND = [
 ("IND-01", "[file:hashes.'SHA-256' = '2d10d13c3f3a045dc12a48e0a484018c053d0e83c607f2796fc9b8307c0d66e5']", "BIN-001 dropper (fiche)", ["unknown"], 15, sco_file("2d10d13c3f3a045dc12a48e0a484018c053d0e83c607f2796fc9b8307c0d66e5"), "declare", "IOC-001, fiche BIN-01"),
 ("IND-02", "[file:hashes.'SHA-256' = 'cdf03e90d85977619f7881a13f59a275812dbf0e4ae29874493728b0ef78ebc9']", "BIN-002 balise (fiche)", ["unknown"], 15, sco_file("cdf03e90d85977619f7881a13f59a275812dbf0e4ae29874493728b0ef78ebc9"), "declare", "IOC-004, fiche BIN-02, journal ligne 2 (taille)"),
 ("IND-03", "[file:hashes.'SHA-256' = 'f4109cd2860816d568c5581edf8ed5df28d35471fa8ff849e9ee2451b69135f0']", "BIN-003 outil d'identifiants (fiche)", ["unknown"], 15, sco_file("f4109cd2860816d568c5581edf8ed5df28d35471fa8ff849e9ee2451b69135f0"), "declare", "IOC-007, fiche BIN-03"),
 ("IND-04", "[domain-name:value = 'cdn-svc-update.test']", "domaine de téléchargement de BIN-002", ["anomalous-activity"], 50, find("domain-name", value="cdn-svc-update.test"), "hypothese", "IOC-013, ALERT-002, journal ligne 2"),
 ("IND-05", "[url:value = 'https://cdn-svc-update.test/win/svchost_update.exe']", "URL de la seconde charge", ["anomalous-activity"], 50, find("url", value="https://cdn-svc-update.test/win/svchost_update.exe"), "hypothese", "IOC-029, ALERT-002, journal ligne 2"),
 ("IND-06", "[ipv4-addr:value = '198.51.100.24']", "destination de la connexion de balise (ALERT-004)", ["anomalous-activity"], 15, find("ipv4-addr", value="198.51.100.24"), "hypothese", "IOC-020, ALERT-004, journal ligne 4"),
 ("IND-07", "[ipv4-addr:value = '203.0.113.28']", "destination de la sortie de 2 469 135 790 octets (ALERT-010)", ["anomalous-activity"], 50, find("ipv4-addr", value="203.0.113.28"), "hypothese", "IOC-024, ALERT-010, journal ligne 10"),
 ("IND-08", "[domain-name:value = 'static-assets-cache.test']", "domaine du « repli C2 » (ALERT-011)", ["anomalous-activity"], 15, find("domain-name", value="static-assets-cache.test"), "hypothese", "IOC-016, ALERT-011, journal ligne 11"),
]
rels = []
def rel(key, rt, s, t, desc, conf, lab):
    rels.append(sdo("relationship", key, relationship_type=rt, source_ref=s, target_ref=t, description=desc, confidence=conf, labels=[lab], created_by_ref=TEAM["id"], object_marking_refs=[TLP]))
IDS = {}
VF = {"IND-01": "2026-03-02T08:31:00Z", "IND-02": "2026-03-02T08:42:00Z", "IND-03": "2026-03-05T14:07:00Z", "IND-04": "2026-03-02T08:42:00Z", "IND-05": "2026-03-02T08:42:00Z", "IND-06": "2026-03-02T09:16:00Z", "IND-07": "2026-03-05T15:31:00Z", "IND-08": "2026-03-06T03:10:00Z"}  # première alerte portant l'indicateur
for i, pat, nm, ty, cf, tgt, lab, src in IND:
    ind = sdo("indicator", i, name=f"[CHALLENGE FICTIF] {i} {nm}", description=f"Indicateur HISTORIQUE (expiré, non destiné à la détection). Sources : {src}. Confiance de l'analyste, pas une cote Admiralty. Statut : {lab}.",
              pattern=pat, pattern_type="stix", pattern_version="2.1", valid_from=VF[i], valid_until="2026-04-02T00:00:00Z", indicator_types=ty, confidence=cf, labels=[lab],
              created_by_ref=TEAM["id"], object_marking_refs=[TLP], external_references=[er(src)])
    new.append(ind); IDS[i] = ind["id"]
    _odt = next((o["id"] for o in objs if o["type"] == "observed-data" and o["object_refs"] == [tgt["id"]]), tgt["id"])
    rel(f"{i}-based-on", "based-on", ind["id"], _odt, f"pattern identique à l'observable exporté par MISP ({lab})", cf, lab)
    rel(f"{i}-indicates", "indicates", ind["id"], CAMP["id"], f"HYPOTHESE : l'indicateur est rattaché au cluster non attribué ; aucune causalité démontrée", min(cf, 15) if lab != "observe" else cf, "hypothese")
for t, ap in AP.items():
    rel(f"camp-uses-{t}", "uses", CAMP["id"], ap["id"], "technique OBSERVEE : " + [x for x in ap["external_references"] if x["source_name"].startswith("Dossier")][0]["description"], 50, "observe")
rel("camp-targets-victime", "targets", CAMP["id"], VICT["id"], "victime du dossier", 50, "observe")
for n, s in SYS.items():
    rel(f"camp-targets-{n}", "targets", CAMP["id"], s["id"], f"événements observés sur {n}", 50, "observe")
for n, m in MAL.items():
    rel(f"camp-uses-{n}", "uses", CAMP["id"], m["id"], "DECLARE par la fiche ; échantillon non fourni ; lien non vérifié", 15, "declare")

# T13 (2026-10-07) : objets de renseignement omis, chacun PROUVÉ par une ligne du journal brut ou par le détail d'une alerte.
#   - tool : logiciels légitimes dont la ligne de commande figure dans les artefacts (powershell.exe, wevtutil.exe : journal brut ; schtasks.exe : détail de l'alerte 3 seulement, donc DECLARE) ;
#   - infrastructure : les quatre rôles réseau décrits par les alertes 2, 4, 10 et 11 (téléchargement, destination de balise, destination de sortie, repli) ; seul le rôle de repli est une HYPOTHESE (I-11).
#   Aucun malware, acteur ou échantillon n'est ajouté ; chaque objet est relié à la campagne et, pour l'infrastructure, aux observables déjà présents dans le bundle.
TOOLS = {}
for key, nm, lab, cf, ev in (
    ("powershell", "powershell.exe", "observe", 50, "ALERT-001, journal ligne 1 : winword.exe -> powershell.exe -enc ... -w hidden"),
    ("wevtutil", "wevtutil.exe", "observe", 50, "ALERT-012, journal ligne 12 : Security 1102 audit log cleared / wevtutil cl Security"),
    ("schtasks", "schtasks.exe", "declare", 15, "ALERT-003 (détail de l'alerte seulement : la commande schtasks /create n'est pas dans le journal brut, I-20)")):
    TOOLS[key] = sdo("tool", "tool-" + key, name=nm, description=f"Utilitaire Windows légitime dont l'emploi figure dans les artefacts ({lab.upper()}). Preuve : {ev}. Aucun échantillon, aucune famille.",
                     created_by_ref=TEAM["id"], object_marking_refs=[TLP], labels=[lab], confidence=cf, external_references=[er(ev, "ALERT-" + ev.split("ALERT-")[1][:3])])
    rel(f"camp-uses-tool-{key}", "uses", CAMP["id"], TOOLS[key]["id"], f"{lab.upper()} : {ev}", cf, lab)
INFRA = {}
for key, nm, ty, fs, lab, cf, ev, scos in (
    ("telechargement", "[CHALLENGE FICTIF] Hébergement du téléchargement (cdn-svc-update.test)", ["hosting-malware"], "2026-03-02T08:42:00Z", "observe", 50,
     "ALERT-002, journal ligne 2 : GET 200 de svchost_update.exe, 421376 octets (IOC-013, IOC-029)", [find("domain-name", value="cdn-svc-update.test"), find("url", value="https://cdn-svc-update.test/win/svchost_update.exe")]),
    ("balise", "[CHALLENGE FICTIF] Destination de la connexion de balise (198.51.100.24)", ["command-and-control"], "2026-03-02T09:16:00Z", "observe", 15,
     "ALERT-004, journal ligne 4 : une connexion vers 198.51.100.24:443 ; le rôle de balise vient du texte de l'alerte, la périodicité n'est pas démontrée (IOC-020)", [find("ipv4-addr", value="198.51.100.24")]),
    ("sortie", "[CHALLENGE FICTIF] Destination de la sortie de données (203.0.113.28)", ["exfiltration"], "2026-03-05T15:31:00Z", "observe", 50,
     "ALERT-010, journal ligne 10 : 2 469 135 790 octets vers 203.0.113.28:8080 en clair (IOC-024)", [find("ipv4-addr", value="203.0.113.28")]),
    ("repli", "[CHALLENGE FICTIF] Repli de commande supposé (static-assets-cache.test)", ["command-and-control"], "2026-03-06T03:10:00Z", "hypothese", 15,
     "ALERT-011, journal ligne 11 : contact du domaine ; le rôle de repli vient du texte de l'alerte et contredit I-11 (IOC-016 vu dès le 3 mars)", [find("domain-name", value="static-assets-cache.test")])):
    INFRA[key] = sdo("infrastructure", "infra-" + key, name=nm, description=f"Rôle réseau décrit par une alerte ({lab.upper()}). Preuve : {ev}. Plage ou domaine de documentation : aucune résolution possible.",
                     infrastructure_types=ty, first_seen=fs, created_by_ref=TEAM["id"], object_marking_refs=[TLP], labels=[lab], confidence=cf, external_references=[er(ev, "ALERT-" + ev.split("ALERT-")[1][:3])])
    rel(f"camp-uses-infra-{key}", "uses", CAMP["id"], INFRA[key]["id"], f"{lab.upper()} : {ev}", cf, lab)
    for k, sc in enumerate(scos):
        rel(f"infra-{key}-consists-{k}", "consists-of", INFRA[key]["id"], sc["id"], "observable déjà présent dans le bundle (export MISP)", cf, lab)
new += list(TOOLS.values()) + list(INFRA.values())
new += rels

def note(key, abstract, content, refs):
    return sdo("note", key, abstract=abstract, content=content, object_refs=refs, authors=["Équipe CTI (challenge fictif)"], created_by_ref=TEAM["id"], object_marking_refs=[TLP])
N0 = note("n-xmisp", "Éléments MISP sans type STIX standard", "Retirés du bundle (voir Export-MISP-brut.json) : nom de tâche planifiée MicrosoftEdgeUpdateTaskMachine (IOC-036), valeur de registre tronquée HKCU\\...\\Run\\WinTelemetry (IOC-038, valeur incomplète dans la source), hôte victime comptabilite-07 (IOC-040, représenté par l'identité système). Le compte svc-backup-temp est représenté par un user-account (chronologie contradictoire : I-03).", [UA["id"], SYS["comptabilite-07"]["id"]])
N1 = note("n-limites", "Limites et incohérences", "21 incohérences ou réserves dans le dossier (I-01 à I-21) : compte svc-backup-temp utilisé avant sa création (I-03), mémo daté avant les faits (I-02), 3 fiches binaires sans échantillon, journal Security de comptabilite-07 effacé le 7 mars. Les dates sont des bornes d'observation.", [CAMP["id"]])
N2 = note("n-attribution", "Attribution hypothétique : INCONNUE", "Aucun élément vérifiable ne désigne un acteur. Le LISEZ-MOI du dossier pédagogique contient une indication d'attribution qui n'est PAS une preuve. Conclusion : cluster non attribué.", [CAMP["id"]])
N3 = note("n-technique", "Identifiant ATT&CK renuméroté", "T1070.001 (ATT&CK <= v18) correspond à T1685.005 en v19 (Defense Impairment). Les galaxies MISP et certaines entités OpenCTI de production portent encore l'ancien identifiant.", [AP["T1685.005"]["id"]])
new += [N0, N1, N2, N3]

body = [o["id"] for o in new if o["type"] in ("campaign", "malware", "attack-pattern", "indicator", "identity", "relationship", "note", "tool", "infrastructure")]
keep = [o["id"] for o in objs if o["type"] in ("grouping", "observed-data", "file", "domain-name", "ipv4-addr", "url", "x509-certificate", "network-traffic", "x-misp-attribute", "note", "relationship")]
REP = sdo("report", "rapport", name="[CHALLENGE FICTIF] Helios Energy — Investigation CTI", description="Rapport STIX du challenge : cluster non attribué, techniques observées, indicateurs historiques. Voir Rapport-validation-STIX.md pour les transformations.",
          published="2026-10-06T12:00:00.000Z", report_types=["threat-report"], object_refs=sorted(set(body + keep)), created_by_ref=TEAM["id"], object_marking_refs=[TLP], confidence=50)
new.append(REP)
# T14 : source et date de collecte portées par chaque SCO (les SCO STIX 2.1 n'ont pas de created_by_ref : propriétés personnalisées préfixées x_helios_)
_COT = {r["valeur_normalisee"].lower(): r for r in _csv.DictReader(open(os.path.join(BASE, "02-Artefacts", "Cotes-Admiralty-IoC.csv"), encoding="utf-8"))}
_INV = {r["id"]: r for r in _csv.DictReader(open(os.path.join(BASE, "02-Artefacts", "Inventaire-IoC.csv"), encoding="utf-8"))}
_SCOS = {o["id"]: o for o in objs if o["type"] in SCO_TYPES}
def _vals(o):
    if o["type"] == "network-traffic": return [v for r in ("src_ref", "dst_ref") if r in o for v in _vals(_SCOS[o[r]])]
    # le chemin du fichier temporaire est normalisé par MISP (%WINDIR% pour C:\\Windows, voir Verification-MISP.md)
    return [o.get("value"), o.get("user_id"), (o.get("name") or "").replace("%WINDIR%", "C:\\Windows")] + list((o.get("hashes") or {}).values())
T14 = 0; T14_SANS = []
for o in objs:
    if o["type"] not in SCO_TYPES: continue
    rows = sorted({_COT[v.lower()]["id"] for v in _vals(o) if v and v.lower() in _COT})
    if not rows: T14_SANS.append(o["id"]); continue
    o["x_helios_source"] = "Dossier Helios (challenge fictif), fourniture/02_indicateurs_40.csv : " + ", ".join(f"{i} ({_INV[i]['emplacement']})" for i in rows)
    o["x_helios_collected_at"] = _INV[rows[0]]["date_acquisition"].replace("Z", ":00Z")
    o["x_helios_admiralty"] = ", ".join(f"{i} {_COT[_INV[i]['valeur_normalisee'].lower()]['cote_equipe']}" for i in rows)
    T14 += 1
assert not T14_SANS, ("SCO sans IoC d'origine", T14_SANS)
for o in objs:
    if o["type"] == "relationship" and not o.get("created_by_ref"):
        o["created_by_ref"] = TEAM["id"]; o["confidence"] = 15; o["labels"] = ["declare"]  # relation exportée par MISP : déclarée par la fiche, non vérifiée (comme les autres relations déclarées)
    if o["id"] == MISP_ORG and not o.get("external_references"):
        o["external_references"] = [{"source_name": "MISP 2.5.46 (export STIX 2.1 de l'événement 6)", "description": "organisation propriétaire de l'événement exporté, date de collecte " + o.get("created", NOW)}]
TEAM["external_references"] = [er("identité de l'équipe auteur de l'analyse, créée le 2026-10-06")]
print("T14 SCO sourcés et datés :", T14)
out = {"type": "bundle", "id": U("bundle", "helios"), "objects": objs + new}
json.dump(out, open(os.path.join(G, "Bundle-STIX.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("T12 observed-data corrigés :", T12); print("objets :", len(out["objects"]), dict(Counter(o["type"] for o in out["objects"])), "| observed-data corrigés :", fixed)
