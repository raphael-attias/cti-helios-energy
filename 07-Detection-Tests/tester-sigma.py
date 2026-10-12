#!/usr/bin/env python3
"""Validation et tests locaux des règles Sigma (pySigma + backend SQLite). Venv dédié :
   /Users/rapatt/Projet/cti-helios-env/.venv/bin/python 07-Detection-Tests/tester-sigma.py

Niveaux distingués (voir Plan-tests.md) :
  1. validation syntaxique : parsing pySigma + validateurs pySigma ;
  2. conversion : backend SQLite avec pipeline de renommage de champs (outil de TEST local, pas un déploiement) ;
  3. test sur événement : exécution du SQL sur une base d'événements ; origine de chaque événement étiquetée
     (dossier / fiche / synthétique / bruit du dossier). Les événements synthétiques ne sont JAMAIS des preuves.
Ce n'est NI un rejeu de bout en bout NI un test Wazuh. Aucune extrapolation à la production."""
import csv, json, os, re, sqlite3, sys, glob
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation
from sigma.validation import SigmaValidator
from sigma.validators.core import validators

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DT = os.path.join(BASE, "07-Detection-Tests")
SRC = os.path.join(BASE, "fourniture", "05_journaux_bruts.log")
KEY = {"process_creation": "windows/process_creation", "process_access": "windows/process_access", "create_remote_thread": "windows/create_remote_thread", "proxy": "proxy"}

def rule_key(ls):
    if ls.get("category") in KEY: return KEY[ls["category"]]
    return f"{ls['product']}/{ls['service']}"

# ------------------------------------------------------------------ 1 + 2 : validation et conversion
files = sorted(glob.glob(os.path.join(DT, "sigma", "DET-*.yml")))
pipe = ProcessingPipeline(name="test-local", priority=10, items=[ProcessingItem(identifier="champs", transformation=FieldMappingTransformation(
    {"cs-method": "cs_method", "c-uri": "c_uri", "sc-status": "sc_status", "id.resp_h": "id_resp_h"}))])
be = sqliteBackend(processing_pipeline=pipe)
val = SigmaValidator(validators=list(validators.values()))
RULES = {}
syn = []
for f in files:
    det = os.path.basename(f)[:7]
    col = SigmaCollection.from_yaml(open(f, encoding="utf-8").read())
    issues = val.validate_rules(col)
    sql = be.convert(col)[0]
    ls = col.rules[0].logsource
    RULES[det] = dict(sql=sql, key=rule_key({"category": ls.category, "product": ls.product, "service": ls.service}), level=str(col.rules[0].level.name).lower(), issues=[str(i)[:160] for i in issues])
    syn.append((det, "OK" if not issues else "ALERTES", "; ".join(RULES[det]["issues"])[:300], sql.replace("SELECT * FROM logs WHERE ", "")[:400]))
os.makedirs(os.path.join(DT, "resultats"), exist_ok=True)
with open(os.path.join(DT, "resultats", "validation-syntaxique-et-conversion.csv"), "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["det", "validation_pySigma", "alertes", "clause_SQL_produite"]); w.writerows(syn)

# ------------------------------------------------------------------ 3 : événements
EV = []
def ev(eid, origine, key, pos, **f):
    EV.append(dict(id=eid, origine=origine, key=key, pos=pos, f=f))

PC, PA, CRT, SEC, PX, ZC, ZN = "windows/process_creation", "windows/process_access", "windows/create_remote_thread", "windows/security", "proxy", "zeek/conn", "zeek/notice"
# événements issus du dossier (journal brut, alertes, fiches)
ev("E01", "dossier:journal l.1", PC, ["DET-001", "DET-002"], ParentImage="winword.exe", Image="powershell.exe", CommandLine="powershell.exe -enc SQBFAFgA... -w hidden")
ev("E02", "dossier:journal l.2", PX, ["DET-003", "DET-004"], cs_method="GET", c_uri="https://cdn-svc-update.test/win/svchost_update.exe", sc_status=200)
ev("E03", "dossier:détail alerte 3 (Image déduite de la commande)", PC, ["DET-005"], Image="schtasks.exe", ParentImage="", CommandLine="schtasks /create /tn MicrosoftEdgeUpdateTaskMachine")
ev("E04", "dossier:journal l.4", ZC, ["DET-006"], id_resp_h="198.51.100.24", id_resp_p=443, orig_bytes=812)
ev("E05", "dossier:journal l.5", ZN, ["DET-008"], msg="scan detected 198.51.100.55 -> 10.20.0.0/16 dports=445,3389")
ev("E06", "dossier:journal l.6", SEC, ["DET-009"], EventID=4624, LogonType=10, TargetUserName="svc-backup-temp")
ev("E07", "dossier:journal l.7", CRT, ["DET-010"], TargetImage="explorer.exe", SourceImage="")
ev("E08", "dossier:journal l.8", PA, ["DET-007"], TargetImage="lsass.exe", GrantedAccess="0x1010", SourceImage="rundll32_helper.dll")
ev("E09", "dossier:journal l.9", SEC, ["DET-011"], EventID=4720, TargetUserName="svc-backup-temp")
ev("E10", "dossier:journal l.10", ZC, ["DET-006", "DET-012"], id_resp_h="203.0.113.28", id_resp_p=8080, orig_bytes=2469135790)
ev("E11", "dossier:journal l.11", PX, ["DET-004"], cs_method="GET", c_uri="https://static-assets-cache.test/", sc_status=200)
ev("E12", "dossier:journal l.12", SEC, ["DET-013"], EventID=1102)
ev("E13", "dossier:journal l.12 (Image déduite)", PC, ["DET-014"], Image="wevtutil.exe", CommandLine="wevtutil cl Security")
ev("E14", "fiche BIN-02 (nom seul)", PC, ["DET-015"], Image="svchost_update.exe")
ev("E15", "fiche BIN-03 (nom seul)", PC, ["DET-015"], Image="rundll32_helper.dll")
# positifs synthétiques
ev("S01", "synthétique", PC, ["DET-001"], ParentImage="C:\\Program Files\\Microsoft Office\\EXCEL.EXE", Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine="powershell.exe -EncodedCommand AAAA -WindowStyle hidden")
ev("S02", "synthétique", PC, ["DET-002"], ParentImage="cmd.exe", Image="powershell.exe", CommandLine="powershell -enc SQBFAFgAIAAoAA==")
ev("S03", "synthétique", PX, ["DET-003"], cs_method="GET", c_uri="http://exemple.test/outils/a.exe", sc_status=200)
ev("S04", "synthétique", PC, ["DET-005"], Image="C:\\Windows\\System32\\schtasks.exe", ParentImage="cmd.exe", CommandLine="schtasks /create /tn MicrosoftEdgeUpdateTaskMachine /tr c:\\x.exe")
ev("S05", "synthétique", PA, ["DET-007"], TargetImage="C:\\Windows\\System32\\lsass.exe", GrantedAccess="0x1410", SourceImage="C:\\Temp\\x.exe")
ev("S06", "synthétique", SEC, ["DET-009"], EventID=4624, LogonType=10, TargetUserName="svc-sql")
ev("S07", "synthétique", CRT, ["DET-010"], TargetImage="C:\\Windows\\explorer.exe", SourceImage="C:\\Users\\Public\\a.exe")
ev("S08", "synthétique", SEC, ["DET-011"], EventID=4720, TargetUserName="svc-test-temp")
ev("S09", "synthétique", ZC, ["DET-012"], id_resp_h="192.0.2.50", id_resp_p=443, orig_bytes=1500000000)
ev("S10", "synthétique", PC, ["DET-014"], Image="C:\\Windows\\System32\\wevtutil.exe", CommandLine="wevtutil.exe cl security")
ev("S11", "synthétique", ZC, ["DET-006"], id_resp_h="203.0.113.14", id_resp_p=443, orig_bytes=100)
ev("S12", "synthétique", PX, ["DET-004"], cs_method="GET", c_uri="https://api-telemetry-eu.test/v2/beacon", sc_status=200)
ev("S13", "synthétique", ZN, ["DET-008"], msg="scan detected 192.0.2.77 -> 10.20.1.0/24 dports=3389,445")
# négatifs synthétiques (sosies bénins)
ev("N01", "synthétique négatif", PC, [], ParentImage="winword.exe", Image="powershell.exe", CommandLine="powershell.exe -File c:\\scripts\\rapport.ps1")
ev("N02", "synthétique négatif", PC, [], ParentImage="excel.exe", Image="powershell.exe", CommandLine="powershell.exe -enc AAAA")
ev("N03", "synthétique négatif", PX, [], cs_method="GET", c_uri="https://exemple.test/doc/rapport.pdf", sc_status=200)
ev("N04", "synthétique négatif", PX, [], cs_method="GET", c_uri="https://exemple.test/outils/b.exe", sc_status=404)
ev("N05", "synthétique négatif", PC, [], Image="schtasks.exe", ParentImage="MicrosoftEdgeUpdate.exe", CommandLine="schtasks /create /tn MicrosoftEdgeUpdateTaskMachineCore")
ev("N06", "synthétique négatif", PC, [], Image="schtasks.exe", ParentImage="cmd.exe", CommandLine="schtasks /query")
ev("N07", "synthétique négatif", PA, [], TargetImage="C:\\Windows\\System32\\lsass.exe", GrantedAccess="0x1010", SourceImage="C:\\Windows\\System32\\csrss.exe")
ev("N08", "synthétique négatif", PA, [], TargetImage="C:\\Windows\\System32\\lsass.exe", GrantedAccess="0x0400", SourceImage="C:\\Temp\\y.exe")
ev("N09", "synthétique négatif", SEC, [], EventID=4624, LogonType=3, TargetUserName="svc-sql")
ev("N10", "synthétique négatif", SEC, [], EventID=4624, LogonType=10, TargetUserName="jdupont")
ev("N11", "synthétique négatif", CRT, [], TargetImage="C:\\Windows\\explorer.exe", SourceImage="C:\\Windows\\System32\\csrss.exe")
ev("N12", "synthétique négatif", CRT, [], TargetImage="C:\\Windows\\notepad.exe", SourceImage="C:\\Temp\\z.exe")
ev("N13", "synthétique négatif", SEC, [], EventID=4720, TargetUserName="jdupont")
ev("N14", "synthétique négatif", ZC, [], id_resp_h="192.0.2.60", id_resp_p=443, orig_bytes=50000000)
ev("N15", "synthétique négatif", SEC, [], EventID=4625, TargetUserName="svc-x")
ev("N16", "synthétique négatif", PC, [], Image="wevtutil.exe", CommandLine="wevtutil qe Security /c:5")
ev("N17", "synthétique négatif", PC, [], Image="wevtutil.exe", CommandLine="wevtutil cl application")
ev("N18", "synthétique négatif", ZN, [], msg="weird activity unknown_protocol")
ev("N19", "synthétique négatif", ZC, [], id_resp_h="192.0.2.1", id_resp_p=443, orig_bytes=900)
ev("N20", "synthétique négatif", PX, [], cs_method="GET", c_uri="https://update.exemple.test/patch.zip", sc_status=200)
ev("N21", "synthétique négatif", PC, [], ParentImage="services.exe", Image="C:\\Windows\\System32\\svchost.exe", CommandLine="svchost.exe -k netsvcs")
ev("N22", "synthétique négatif", SEC, [], EventID=4634, TargetUserName="jdupont")
# bruit du dossier : 360 lignes syslog
n = 0
for line in open(SRC, encoding="utf-8").read().splitlines():
    if not re.match(r"\d{4}-\d\d-\d\dT", line):
        n += 1; ev(f"B{n:03d}", "bruit du dossier", "linux/syslog", [], msg=line)

cols = sorted({k for e in EV for k in e["f"]})
INT = {"EventID", "LogonType", "sc_status", "id_resp_p", "orig_bytes"}
db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE logs (eid TEXT, origine TEXT, logsrc TEXT, " + ", ".join(f"{c} {'INTEGER' if c in INT else 'TEXT'}" for c in cols) + ")")
for e in EV:
    vals = [e["f"].get(c, None if c in INT else "") for c in cols]
    db.execute("INSERT INTO logs VALUES (?,?,?," + ",".join("?" * len(cols)) + ")", [e["id"], e["origine"], e["key"]] + vals)

rows, summ = [], []
tid = 0
for det, r in sorted(RULES.items()):
    matched_all = {x[0] for x in db.execute(r["sql"].replace("SELECT *", "SELECT eid"))}   # contrôle croisé : sans restriction de logsource
    in_ls = [e for e in EV if e["key"] == r["key"]]
    tp = fp = fn = tn = 0
    for e in in_ls:
        exp = det in e["pos"]; got = e["id"] in matched_all
        res = "OK" if exp == got else ("FAUX POSITIF" if got else "FAUX NEGATIF")
        tp += exp and got; fn += exp and not got; fp += got and not exp; tn += (not exp) and (not got)
        if e["origine"] != "bruit du dossier":
            tid += 1
            typ = ("positif réel" if e["origine"].startswith(("dossier", "fiche")) else "positif synthétique") if exp else ("négatif synthétique" if "négatif" in e["origine"] else "autre événement du même logsource")
            rows.append([f"TEST-{tid:03d}", det, typ, e["id"], e["origine"], "déclenche" if exp else "ne déclenche pas", "déclenche" if got else "ne déclenche pas", res])
    cross = sorted(x for x in matched_all if next(e for e in EV if e["id"] == x)["key"] != r["key"])
    noise_hits = sorted(x for x in matched_all if x.startswith("B"))
    tid += 1
    rows.append([f"TEST-{tid:03d}", det, "bruit du dossier (agrégé)", "B001..B360", "bruit du dossier (syslog Linux, 360 lignes, applicable seulement comme contrôle croisé)", "ne déclenche pas", f"{len(noise_hits)} déclenchement(s)", "OK" if not noise_hits else "FAUX POSITIF"])
    summ.append(dict(det=det, logsource=r["key"], evenements_logsource=len(in_ls), tp=tp, fn=fn, fp=fp, tn=tn, croise=len(cross), bruit=len(noise_hits), total_parcourus=len(EV)))
with open(os.path.join(DT, "Resultats-tests.csv"), "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["test_id", "det", "type", "evenement", "origine", "attendu", "obtenu", "resultat"]); w.writerows(rows)
with open(os.path.join(DT, "resultats", "synthese-par-regle.csv"), "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=list(summ[0].keys())); w.writeheader(); w.writerows(summ)
bad = [r for r in rows if r[-1] != "OK"]
print(f"règles : {len(RULES)} | événements en base : {len(EV)} (dossier/fiche 15, synthétiques positifs 13, négatifs 22, bruit 360) | tests détaillés : {len(rows)} | écarts : {len(bad)}")
for s in summ:
    print(" ", s)
for b in bad:
    print("  ÉCART", b)
