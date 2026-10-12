#!/usr/bin/env python3
"""Construit jeux-tests/events-wazuh.tsv : événements du dossier (lignes ISO 1 à 12 du journal brut, INCHANGÉES) + événements SYNTHETIQUES
(étiquetés) au même format. Colonnes : id, origine, ids de règles attendus (séparés par des virgules, vide = aucun), ligne de journal."""
import os, re
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = open(os.path.join(BASE, "fourniture", "05_journaux_bruts.log"), encoding="utf-8").read().splitlines()
iso = [l for l in src if re.match(r"\d{4}-\d\d-\d\dT", l)]
assert len(iso) == 12
exp = {1: "130101,130102", 2: "130103,130104", 3: "130105", 4: "130106", 5: "130108", 6: "130109", 7: "130110", 8: "130107", 9: "130111", 10: "130106,130112", 11: "130104", 12: "130113"}
rows = [(f"W{n:02d}", f"dossier:journal l.{n}", exp[n], iso[n - 1]) for n in range(1, 13)]
T = "2026-03-09T10:00:00Z"
syn = [
 ("SP01", "130101", f"{T} poste-test Sysmon: Process Create: EXCEL.EXE -> powershell.exe -EncodedCommand AAAA -WindowStyle hidden"),
 ("SP02", "130102", f"{T} poste-test Sysmon: Process Create: cmd.exe -> powershell.exe -enc SQBFAFgAIAAoAA=="),
 ("SP03", "130103", f"{T} poste-test Squid: GET http://exemple.test/outils/a.exe 200 1024"),
 ("SP04", "130104", f"{T} poste-test Squid: GET https://api-telemetry-eu.test/v2/beacon 200 10"),
 ("SP05", "130105", f"{T} poste-test Sysmon: Scheduled Task Created: MicrosoftEdgeUpdateTaskMachine"),
 ("SP06", "130106", f"{T} poste-test Zeek: conn 203.0.113.14:443 duration=0.3 orig_bytes=500 (beacon)"),
 ("SP07", "130107", f"{T} poste-test Sysmon: Process Access: target=lsass.exe granted=0x1410 by C:\\Temp\\x.exe"),
 ("SP08", "130108", f"{T} poste-test Zeek: scan detected 192.0.2.77 -> 10.20.1.0/24 dports=3389,445"),
 ("SP09", "130109", f"{T} srv-test Security: 4624 Logon type=10 RDP account=svc-sql time=02:10"),
 ("SP10", "130110", f"{T} srv-test Sysmon: CreateRemoteThread into explorer.exe RWX region"),
 ("SP11", "130111", f"{T} dc-test Security: 4720 User created svc-test-temp / 4726 deleted 5m later"),
 ("SP12", "130112", f"{T} dc-test Zeek: large outbound 192.0.2.50:443 bytes=1500000000 cleartext"),
 ("SP13", "130113", f"{T} poste-test Security: 1102 audit log cleared / wevtutil cl Security"),
 ("SP14", "130114", f"{T} poste-test Sysmon: Process Create: cmd.exe -> wevtutil.exe cl Security"),
 ("SP15", "130115", f"{T} poste-test Sysmon: Process Create: services.exe -> svchost_update.exe -k x"),
]
neg = [
 ("SN01", f"{T} poste-test Sysmon: Process Create: winword.exe -> powershell.exe -File c:\\scripts\\rapport.ps1"),
 ("SN02", f"{T} poste-test Sysmon: Process Create: excel.exe -> powershell.exe -enc AAAA"),
 ("SN03", f"{T} poste-test Squid: GET https://exemple.test/doc/rapport.pdf 200 1024"),
 ("SN04", f"{T} poste-test Squid: GET https://exemple.test/outils/b.exe 404 0"),
 ("SN05", f"{T} poste-test Sysmon: Scheduled Task Created: MicrosoftEdgeUpdateTaskMachineCore"),
 ("SN06", f"{T} poste-test Zeek: conn 192.0.2.1:443 duration=0.1 orig_bytes=900"),
 ("SN07", f"{T} poste-test Sysmon: Process Access: target=lsass.exe granted=0x1010 by C:\\Windows\\System32\\csrss.exe"),
 ("SN08", f"{T} poste-test Sysmon: Process Access: target=lsass.exe granted=0x0400 by C:\\Temp\\y.exe"),
 ("SN09", f"{T} srv-test Security: 4624 Logon type=3 RDP account=svc-sql time=02:10"),
 ("SN10", f"{T} srv-test Security: 4624 Logon type=10 RDP account=jdupont time=02:10"),
 ("SN11", f"{T} srv-test Sysmon: CreateRemoteThread into notepad.exe RWX region"),
 ("SN12", f"{T} dc-test Security: 4720 User created jdupont / 4726 deleted 5m later"),
 ("SN13", f"{T} dc-test Zeek: large outbound 192.0.2.60:443 bytes=50000000 cleartext"),
 ("SN14", f"{T} poste-test Sysmon: Process Create: cmd.exe -> wevtutil.exe qe Security /c:5"),
 ("SN15", f"{T} poste-test Sysmon: Process Create: cmd.exe -> wevtutil.exe cl application"),
 ("SN16", f"{T} poste-test Zeek: weird activity unknown_protocol"),
 ("SN17", f"{T} poste-test Squid: GET https://update.exemple.test/patch.zip 200 4096"),
 ("SN18", f"{T} poste-test Sysmon: Process Create: services.exe -> svchost.exe -k netsvcs"),
]
for i, e, l in syn: rows.append((i, "synthétique positif", e, l))
for i, l in neg: rows.append((i, "synthétique négatif", "", l))
ORDER = ["130101","130102","130103","130104","130105","130112","130106","130107","130108","130109","130110","130111","130113","130114","130115"]
shadow = []
new = []
for i, o, e, l in rows:
    ids = [x for x in e.split(",") if x]
    if len(ids) > 1:
        ids.sort(key=ORDER.index); shadow.append((i, ids[0], ",".join(ids[1:])))
    new.append((i, o, ids[0] if ids else "", l))
rows = new
os.makedirs(os.path.join(BASE, "07-Detection-Tests", "jeux-tests"), exist_ok=True)
with open(os.path.join(BASE, "07-Detection-Tests", "jeux-tests", "ombrage.csv"), "w", encoding="utf-8") as f:
    f.write("evenement,regle_qui_declenche_wazuh,regles_ombragees\n")
    for a, b, c in shadow: f.write(f"{a},{b},{c.replace(',', ' ')}\n")
with open(os.path.join(BASE, "07-Detection-Tests", "jeux-tests", "events-e2e.log"), "w", encoding="utf-8") as f:
    for r in rows: f.write(r[3] + "\n")
with open(os.path.join(BASE, "07-Detection-Tests", "jeux-tests", "events-wazuh.tsv"), "w", encoding="utf-8") as f:
    for r in rows: f.write("\t".join(r) + "\n")
print(len(rows), "événements :", sum(1 for r in rows if r[1].startswith("dossier")), "du dossier,", len(syn), "synthétiques positifs,", len(neg), "synthétiques négatifs")
