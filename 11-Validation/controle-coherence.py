#!/usr/bin/env python3
"""Contrôle final de cohérence du dossier (exécutable, sans réseau). Sortie archivée dans controle-coherence-sortie.txt.
Usage : /Users/rapatt/Projet/cti-helios-env/.venv/bin/python 11-Validation/controle-coherence.py"""
import csv, glob, hashlib, json, os, re, sys
import pymupdf
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda p: os.path.join(B, p)
ok, ko = [], []
def chk(name, cond, detail=""):
    (ok if cond else ko).append(f"{name}{' : ' + detail if detail else ''}")
txt = lambda p: open(R(p), encoding="utf-8").read()

# 1. originaux
EXP = {"00_LISEZ-MOI.md": "b07b83f22c9d07560207528a6a612eee17864273748a90d73c1c5e0dcbc346fd", "01_fiches_analyse_binaires.md": "ec40b1649a4b52161d5acfa6a230ca05c2ca4e7683fbd997db71dbf5d341e734",
       "02_indicateurs_40.csv": "48b23612f54456310c71402f43c68cc05d68ca70900b00e2e7e269c4ee23b862", "02_indicateurs_40.json": "41266a1f9aad fd712d00208d".replace(" ", "")}
EXP["02_indicateurs_40.json"] = "41266a1f9aad" ; # préfixe seulement, complété ci-dessous
FULL = {"02_indicateurs_40.json": "41266a1f9aadfb7ef8bf35852138f974d035a9c28589763fd56fd89bb9b4f7f4", "03_alertes_siem_12.csv": "fd712d00208d731e5a0fa0a8d867813ab6590916c82c29d4f8a9a2a1eb49a5e7",
        "04_memo_technique_SOC.md": "9cc2e0edf6e7697f08626215b66b7425aab4e8dfbfde1d397cf107975eca23a2", "05_journaux_bruts.log": "bc55524ab7f953e293ebc329c7353e3962c0f4b616a716445763ea278a7d49bd"}
EXP.update(FULL)
for f, h in EXP.items():
    chk(f"original inchangé {f}", hashlib.sha256(open(R("fourniture/" + f), "rb").read()).hexdigest() == h)

# 2. arborescence cible
TREE = """00-Pilotage/Tableau-de-bord.md 00-Pilotage/Matrice-exigences.csv 00-Pilotage/Journal-decisions.md 00-Pilotage/Decisions-et-limites-finales.md 00-Pilotage/Inventaire-infrastructure.md
01-Cadrage/Note-cadrage.md 01-Cadrage/Planning-35h.md 01-Cadrage/Roles-et-communication.md 02-Artefacts/Inventaire-artefacts.csv 02-Artefacts/Inventaire-IoC.csv 02-Artefacts/Inventaire-alertes.csv
02-Artefacts/Inventaire-binaires.csv 02-Artefacts/Integrite-et-provenance.md 03-Sources/Registre-sources.csv 03-Sources/Journal-collecte.csv 04-Analyse/Analyse-IoC.md 04-Analyse/Analyse-alertes.md
04-Analyse/Analyse-binaires.md 04-Analyse/Chronologie.csv 04-Analyse/Matrice-ATTACK.csv 04-Analyse/Diamond-Model.md 04-Analyse/Hypotheses-et-attribution.md 04-Analyse/Cartographie-SI.md
04-Analyse/Matrice-risques-CID.csv 99-Historique/Plan-ingestion.md 05-Plateformes/Manifeste-ingestion.json 05-Plateformes/Journal-ingestion.csv 05-Plateformes/Verification-MISP.md
05-Plateformes/Verification-OpenCTI.md 05-Plateformes/Verification-Cortex.md 06-STIX-Graphe/Bundle-STIX.json 06-STIX-Graphe/Rapport-validation-STIX.md 06-STIX-Graphe/Inventaire-objets-STIX.csv
06-STIX-Graphe/Graphe-CTI.png 06-STIX-Graphe/Script-generation-graphe.py 07-Detection-Tests/Plan-tests.md 07-Detection-Tests/Resultats-tests.csv 07-Detection-Tests/Limites-detection.md
08-Rapports/Rapport-strategique.md 08-Rapports/Rapport-strategique.pdf 08-Rapports/Rapport-tactique.md 08-Rapports/Rapport-tactique.pdf 08-Rapports/Note-attribution.md
08-Rapports/Note-reglementaire-ANSSI.md 08-Rapports/Note-partage-communautaire.md 09-Journal-mission/J1-Cadrage-triage.md 09-Journal-mission/J2-Correlation-enrichissement.md
09-Journal-mission/J3-Chaine-attaque-attribution.md 09-Journal-mission/J4-Rapports-detections.md 09-Journal-mission/J5-Conformite-graphe-soutenance.md 10-Soutenance/Plan-soutenance.md
10-Soutenance/Support-soutenance.pdf 10-Soutenance/Questions-reponses.md 10-Soutenance/Resume-prez-doc.md 11-Validation/Couverture-competences.md 99-Historique/Bilan-final-session.md README.md""".split()
miss = [p for p in TREE if not os.path.exists(R(p))]
chk("arborescence cible : fichiers présents", not miss, f"{len(TREE) - len(miss)}/{len(TREE)} ; manquants : {miss}")
chk("dossiers sigma, wazuh, jeux-tests non vides", all(glob.glob(R(d + "/*")) for d in ("07-Detection-Tests/sigma", "07-Detection-Tests/wazuh", "07-Detection-Tests/jeux-tests")))

# 3. PDF
pg = {"01-Cadrage/Note-cadrage.pdf": (2, 2), "08-Rapports/Rapport-strategique.pdf": (2, 3), "08-Rapports/Rapport-tactique.pdf": (8, 12), "08-Rapports/Note-reglementaire-ANSSI.pdf": (1, 1),
      "08-Rapports/Note-partage-communautaire.pdf": (1, 1), "10-Soutenance/Support-soutenance.pdf": (10, 20)}
for p, (a, b) in pg.items():
    if os.path.exists(R(p)):
        n = len(pymupdf.open(R(p))); t = "".join(pg_.get_text() for pg_ in pymupdf.open(R(p)))
        chk(f"pagination {p}", a <= n <= b, f"{n} pages (attendu {a} à {b}) ; texte extractible {len(t)} caractères")
    else:
        chk(f"pagination {p}", False, "absent")

# 4. chiffres croisés
bun = json.load(open(R("06-STIX-Graphe/Bundle-STIX.json"), encoding="utf-8"))["objects"]
from collections import Counter
c = Counter(o["type"] for o in bun)
chk("bundle : 152 objets", len(bun) == 152)
chk("bundle : 8 indicateurs, 8 attack-pattern, 3 malware, 1 campaign, 1 report", c["indicator"] == 8 and c["attack-pattern"] == 8 and c["malware"] == 3 and c["campaign"] == 1 and c["report"] == 1)
chk("bundle : 44 relations", c["relationship"] == 44)
chk("rapport STIX cite 152 et 44", "152" in txt("06-STIX-Graphe/Rapport-validation-STIX.md") and "| Relations | 44 |" in txt("06-STIX-Graphe/Rapport-validation-STIX.md"))
chk("aucun acteur dans le bundle", not any(o["type"] in ("intrusion-set", "threat-actor") for o in bun) and "fin7" not in json.dumps(bun).lower() and "carbanak" not in json.dumps(bun).lower())
ioc = list(csv.DictReader(open(R("02-Artefacts/Inventaire-IoC.csv"), encoding="utf-8")))
chk("inventaire : 40 IoC, 12 alertes, 3 binaires", len(ioc) == 40 and len(list(csv.reader(open(R("02-Artefacts/Inventaire-alertes.csv"), encoding="utf-8")))) == 13 and len(list(csv.reader(open(R("02-Artefacts/Inventaire-binaires.csv"), encoding="utf-8")))) == 4)
reg = list(csv.DictReader(open(R("07-Detection-Tests/Registre-regles.csv"), encoding="utf-8")))
chk("15 règles Sigma, 11 directes, 3 IOC, 1 chasse", len(reg) == 15 and Counter(r["fondement"] for r in reg) == {"DIRECTE": 11, "IOC": 3, "CHASSE": 1})
chk("fichiers Sigma présents (15)", len(glob.glob(R("07-Detection-Tests/sigma/DET-*.yml"))) == 15)
rt = list(csv.DictReader(open(R("07-Detection-Tests/Resultats-tests.csv"), encoding="utf-8")))
chk("Sigma : 0 écart dans 162 tests", len(rt) == 162 and all(r["resultat"] == "OK" for r in rt))
wz = list(csv.DictReader(open(R("07-Detection-Tests/Resultats-wazuh.csv"), encoding="utf-8")))
chk("Wazuh : 180 lignes, tout conforme", len(wz) == 180 and all(r["resultat"] == "OK" for r in wz))
al = [json.loads(l) for l in open(R("07-Detection-Tests/resultats/wazuh-production-alertes-helios.json"), encoding="utf-8") if l.strip()]
chk("Wazuh production : 27 alertes archivées, niveaux 4 à 7", len(al) == 27 and {a["rule"]["level"] for a in al} <= {4, 5, 7})
chk("Wazuh production : aucune alerte niveau >= 10 (seuil TheHive)", all(a["rule"]["level"] < 10 for a in al))
mat = list(csv.DictReader(open(R("04-Analyse/Matrice-analyse-alertes.csv"), encoding="utf-8")))
chk("matrice des alertes : 12 lignes, 22 colonnes", len(mat) == 12 and len(mat[0]) == 22)
chk("T1070.001 : plus utilisé comme technique retenue", all("T1070.001" not in r["technique_ATTACK_proposee"] for r in mat))
chk("alerte 8 : T1055.012 non retenue", "T1055.012" not in next(r for r in mat if r["id"] == "ALERT-008")["technique_ATTACK_proposee"])
chk("alerte 9 : T1543.003 non retenue", "T1543.003" not in next(r for r in mat if r["id"] == "ALERT-009")["technique_ATTACK_proposee"])
man = json.load(open(R("05-Plateformes/Manifeste-OpenCTI.json"), encoding="utf-8"))
chk("manifeste OpenCTI : 27 observables, 8 indicateurs, 0 domaine", len(man["observables"]) == 27 and len(man["indicateurs"]) == 8 and all(o["type"] != "Domain-Name" for o in man["observables"]))
ids = json.load(open(R("05-Plateformes/IDs-OpenCTI.json"), encoding="utf-8"))
chk("identifiants OpenCTI archivés (rapport, incident, 3 notes)", all(k in ids for k in ("REPORT", "INC", "N-ALERTES", "N-LIMITES", "N-ATTRIB")))
g = txt("05-Plateformes/Guide-consultation-OpenCTI.md")
chk("guide : liens du rapport et de l'incident corrects", ids["REPORT"] in g and ids["INC"] in g)
chk("guide : statut des contrôles d'interface daté et réserves listées", "revus dans les interfaces les 2026-10-06 et 2026-10-07" in g and "Réserves" in g)
for p in ("04-Analyse/Analyse-IoC.md",):
    chk(f"{p} : somme 9+3+1+25+2 = 40", "9 + 3 + 1 + 25 + 2 = 40" in txt(p))
stale = {"00-Pilotage/Tableau-de-bord.md": ["3 / 35 (8,6", "3 / 36 (8,3"], "01-Cadrage/Note-cadrage.md": ["17 incohérences"], "08-Rapports/Rapport-strategique.md": ["17 incohérences"]}
for p, pats in stale.items():
    if os.path.exists(R(p)):
        t = txt(p); chk(f"{p} : aucune valeur périmée {pats}", not any(x in t for x in pats))
# 5. secrets, binaires, liens, tirets
SECRET = re.compile(r"(?i)(api[_-]?key|token|secret|passw(or)?d)\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY|Bearer\s+[A-Za-z0-9._\-]{20,}")
SKIP = {"fourniture"}
hits, bins, deadlinks, dashes = [], [], [], []
for root, dirs, files in os.walk(B):
    dirs[:] = [d for d in dirs if d not in SKIP and not d.startswith(".")]
    for f in files:
        p = os.path.join(root, f); rel = os.path.relpath(p, B)
        head = open(p, "rb").read(4)
        if head[:2] == b"MZ" or head[:4] == b"\x7fELF" or head[:4] in (b"\xcf\xfa\xed\xfe", b"\xd0\xcf\x11\xe0") or f.lower().endswith((".exe", ".dll", ".xlsm", ".docm", ".jar", ".bin")):
            bins.append(rel)
        if f.endswith((".md", ".csv", ".py", ".json", ".yml", ".xml", ".sh", ".txt", ".tsv", ".log")):
            t = open(p, encoding="utf-8", errors="ignore").read()
            if f != "controle-coherence.py" and SECRET.search(t): hits.append(rel)
            if f.endswith(".md"):
                for m in re.finditer(r"\]\(([^)#\s]+)\)", t):
                    L = m.group(1)
                    if L.startswith(("http", "mailto", "file:")): continue
                    if not os.path.exists(os.path.normpath(os.path.join(root, L))): deadlinks.append(f"{rel} -> {L}")
                if "—" in t or "–" in t: dashes.append(rel)
chk("aucun secret détecté (motifs courants)", not hits, str(hits))
chk("aucun binaire ou document Office dans le dossier de mission", not bins, str(bins))
chk("liens internes Markdown résolus", not deadlinks, f"{len(deadlinks)} cassés : {deadlinks[:6]}")
print("== OK ==", len(ok)); [print("  OK ", x) for x in ok]
print("== ÉCARTS ==", len(ko)); [print("  KO ", x) for x in ko]
print("== Information : fichiers .md contenant un tiret long (noms exacts demandés ou citations de la source) :", len(dashes), dashes)
sys.exit(1 if ko else 0)
