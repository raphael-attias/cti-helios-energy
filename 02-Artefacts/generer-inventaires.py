#!/usr/bin/env python3
"""Génère les inventaires du challenge CTI Helios Energy à partir de fourniture/.

Lecture seule sur fourniture/ ; écrit uniquement dans 02-Artefacts/.
Dépendances : bibliothèque standard uniquement.
Relancer : python3 02-Artefacts/generer-inventaires.py
Un contrôle de cohérence (anomalies) est écrit dans Controle-coherence-sources.csv.
"""
import csv, hashlib, json, re, os, collections
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BASE, "fourniture")
OUT = os.path.join(BASE, "02-Artefacts")
ACQ = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")  # date d'acquisition = date d'exécution du script


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def rel(p):
    return os.path.relpath(p, BASE)


def write_csv(name, header, rows):
    with open(os.path.join(OUT, name), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def refang(v):
    return v.replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")


# ---------------------------------------------------------------- fichiers sources
files = sorted(os.listdir(SRC))
fhash = {f: sha256_file(os.path.join(SRC, f)) for f in files}
art_rows = []
for i, f in enumerate(files, 1):
    p = os.path.join(SRC, f)
    n = sum(1 for _ in open(p, "rb"))
    art_rows.append([f"ART-{i:03d}", rel(p), f, os.path.getsize(p), n, fhash[f],
                     datetime.fromtimestamp(os.path.getmtime(p), timezone.utc).strftime("%Y-%m-%dT%H:%MZ"), ACQ])
write_csv("Inventaire-artefacts.csv",
          ["id", "chemin_relatif", "fichier", "taille_octets", "lignes", "sha256", "mtime_fichier_utc", "date_acquisition_utc"],
          art_rows)

# ---------------------------------------------------------------- IoC
csv_path = os.path.join(SRC, "02_indicateurs_40.csv")
json_path = os.path.join(SRC, "02_indicateurs_40.json")
raw = list(csv.DictReader(open(csv_path, encoding="utf-8")))
js = json.load(open(json_path, encoding="utf-8"))
HEXLEN = {"sha256": 64, "sha1": 40, "md5": 32, "sha1-cert": 40}
seen = collections.Counter()
ioc_rows, anomalies = [], []
for r in raw:
    n = int(r["#"])
    t, v = r["type"], r["valeur"]
    norm, transfo, statut = v, [], "NON VERIFIE (aucun enrichissement)"
    if t in HEXLEN:
        norm = v.lower()
        if norm != v:
            transfo.append("casse -> minuscules")
        if not re.fullmatch(r"[0-9a-f]{%d}" % HEXLEN[t], norm):
            statut = "INVALIDE (format)"
            anomalies.append((f"IOC-{n:03d}", "format", f"{t} de longueur/charset invalide"))
    if t in ("domain", "url"):
        norm = refang(v).lower()
        if norm != v:
            transfo.append("defang retiré (refang) / minuscules")
    if t == "ipv4":
        a = [int(x) for x in v.split(".")]
        assert len(a) == 4 and all(0 <= x <= 255 for x in a)
    seen[(t, norm)] += 1
    jr = js[n - 1]
    same = (jr["type"], jr["valeur"], jr["contexte"], jr["premiere_vue"], jr["confiance_admiralty"]) == \
           (t, v, r["contexte"], r["premiere_vue"], r["confiance_admiralty"])
    if not same:
        anomalies.append((f"IOC-{n:03d}", "csv_vs_json", "ligne CSV différente de la ligne JSON"))
    limites = "Fournie par le SOC ; aucune vérification externe (plages de documentation RFC 5737 / domaines .test)" \
        if t in ("ipv4", "domain", "url") else "Valeur fournie par le SOC ; échantillon non fourni, hash non recalculable"
    ioc_rows.append([f"IOC-{n:03d}", "02_indicateurs_40.csv", fhash["02_indicateurs_40.csv"], f"ligne {n+1}", t, v, norm,
                     ACQ, r["premiere_vue"], "UTC (Z)", "; ".join(transfo) or "aucune", "SOC Helios (CSV/JSON fournis)",
                     r["confiance_admiralty"], r["contexte"], statut, limites])
dups = [(k, c) for k, c in seen.items() if c > 1]
write_csv("Inventaire-IoC.csv",
          ["id", "fichier_source", "sha256_fichier_source", "emplacement", "type", "valeur_originale", "valeur_normalisee",
           "date_acquisition", "date_evenement_premiere_vue", "fuseau", "transformations", "source", "admiralty_fournie_SOC",
           "contexte_original", "statut_validation", "limites"], ioc_rows)

# ---------------------------------------------------------------- alertes
al_path = os.path.join(SRC, "03_alertes_siem_12.csv")
alerts = list(csv.DictReader(open(al_path, encoding="utf-8")))
al_rows, prev = [], None
for a in alerts:
    n = int(a["alerte"])
    ts = a["horodatage"]
    if prev and ts < prev:
        anomalies.append((f"ALERT-{n:03d}", "ordre_chrono", f"{ts} antérieure à une alerte qui la précède dans le fichier ({prev}) : l'alerte 5 est hors séquence alors que le LISEZ-MOI annonce l'ordre chronologique"))
    prev = max(prev, ts) if prev else ts
    al_rows.append([f"ALERT-{n:03d}", "03_alertes_siem_12.csv", fhash["03_alertes_siem_12.csv"], f"ligne {n+1}", ts, "UTC (Z)", ACQ,
                    a["source"], a["hote"], a["intitule"], a["technique_attck"], a["severite"], a["detail"],
                    "TECHNIQUE ATT&CK FOURNIE PAR LE SIEM, NON VERIFIEE", "Détail brut seulement ; pas de log d'origine joint sauf correspondance dans 05_journaux_bruts.log"])
write_csv("Inventaire-alertes.csv",
          ["id", "fichier_source", "sha256_fichier_source", "emplacement", "horodatage_original", "fuseau", "date_acquisition",
           "source_log", "hote", "intitule", "technique_attck_fournie", "severite", "detail", "statut_validation", "limites"], al_rows)

# ---------------------------------------------------------------- binaires (fiches uniquement)
fiche = open(os.path.join(SRC, "01_fiches_analyse_binaires.md"), encoding="utf-8").read()
blocks = re.split(r"\n## (BIN-\d+) \u2014 ", fiche)[1:]
ioc_by_val = {r["valeur"].lower(): int(r["#"]) for r in raw}
bin_rows = []
for k in range(0, len(blocks), 2):
    bid, body = blocks[k], blocks[k + 1]
    name = body.splitlines()[0].strip()
    g = lambda lab: re.search(r"\*\*%s\*\* : `?([^`\n]+)`?" % lab, body).group(1).strip()
    s256, s1, m5 = g("SHA-256"), g("SHA-1"), g("MD5")
    size = int(g("Taille").split()[0])
    xref = []
    for lab, h in (("sha256", s256), ("sha1", s1), ("md5", m5)):
        n = ioc_by_val.get(h.lower())
        xref.append(f"{lab}->IOC-{n:03d}" if n else f"{lab}->ABSENT du CSV")
        if not n:
            anomalies.append((f"BIN-{bid[-2:]}", "hash_fiche_vs_csv", f"{lab} {h} absent du CSV IoC"))
    bin_rows.append([f"BIN-{int(bid[-2:]):03d}", bid, name, "01_fiches_analyse_binaires.md", fhash["01_fiches_analyse_binaires.md"],
                     s256, s1, m5, size, g("Type"), g("Première apparition"), g("Verdict"), "; ".join(xref),
                     "ECHANTILLON NON FOURNI : empreintes non recalculables, aucune analyse statique possible",
                     "Comportement = déclaré par la fiche (non observé par nous)"])
write_csv("Inventaire-binaires.csv",
          ["id", "id_source", "nom", "fichier_source", "sha256_fichier_source", "sha256", "sha1", "md5", "taille_octets", "type_declare",
           "premiere_apparition", "verdict_fiche", "correspondance_IoC", "statut_validation", "limites"], bin_rows)

# ---------------------------------------------------------------- journal brut : volumétrie
log = open(os.path.join(SRC, "05_journaux_bruts.log"), encoding="utf-8").read().splitlines()
iso = [l for l in log if re.match(r"\d{4}-\d\d-\d\dT", l)]
sysl = [l for l in log if l not in iso]
stats = {
    "lignes_total": len(log), "lignes_iso8601_Z": len(iso), "lignes_syslog_sans_annee_ni_fuseau": len(sysl),
    "iso_vs_alertes": f"{len(iso)} lignes ISO pour {len(alerts)} alertes",
    "syslog_premiere": sysl[0][:15], "syslog_derniere": sysl[-1][:15],
}
# alertes <-> journal : correspondance horodatage + hôte
for a in alerts:
    hit = [l for l in iso if l.startswith(a["horodatage"]) and a["hote"] in l]
    if len(hit) != 1:
        anomalies.append((f"ALERT-{int(a['alerte']):03d}", "alerte_sans_log", f"{len(hit)} ligne(s) ISO au même horodatage/hôte"))
json.dump(stats, open(os.path.join(OUT, "Volumetrie-journal.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)

# ---------------------------------------------------------------- bilan comptage
write_csv("Bilan-comptage.csv", ["mesure", "valeur"], [
    ["IoC lignes CSV d'origine", len(raw)], ["IoC lignes JSON", len(js)],
    ["IoC valeurs uniques (type+valeur normalisée)", len(seen)], ["IoC doublons", len(dups)],
    ["IoC valeurs invalides", sum(1 for r in ioc_rows if r[14].startswith("INVALIDE"))],
    ["Alertes", len(alerts)], ["Fiches binaires", len(bin_rows)], ["Échantillons binaires fournis", 0],
    ["Lignes journal brut", len(log)], ["Lignes journal ISO (corrélées aux alertes)", len(iso)],
    ["Lignes journal syslog (bruit)", len(sysl)],
])
write_csv("Controle-coherence-sources.csv", ["objet", "categorie", "constat_automatique"], anomalies)
print("OK :", len(raw), "IoC,", len(alerts), "alertes,", len(bin_rows), "fiches binaires,", len(anomalies), "anomalies automatiques")
for a in anomalies:
    print(" -", *a)
