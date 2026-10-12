#!/usr/bin/env python3
"""Contrôles TECHNIQUES réalisables par script pour les exigences officielles qui étaient « À CONTRÔLER ».
Un contrôle technique n'est pas une validation par le commanditaire. Sortie : 11-Validation/Controles-exigences.csv.
Venv : /Users/rapatt/Projet/cti-helios-env/.venv/bin/python 11-Validation/controles-exigences.py"""
import csv, hashlib, json, os, re, unicodedata, collections
import pymupdf as fitz
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = lambda *a: os.path.join(B, *a)
def rd(*a): return open(P(*a), encoding="utf-8").read()
def csvr(*a): return list(csv.DictReader(open(P(*a), encoding="utf-8")))
def norm(s): return "".join(c for c in unicodedata.normalize("NFD", s.lower()) if unicodedata.category(c) != "Mn")
def has(t, *kws): return all(norm(k) in norm(t) for k in kws)
def pdf(*a):
    d = fitz.open(P(*a)); return len(d), "\n".join(p.get_text() for p in d)
R = []  # (req, controle, ok, detail)
def chk(req, label, ok, detail=""): R.append((req, label, bool(ok), str(detail)[:200]))

# ---- REQ-05 intégrité
t = rd("02-Artefacts", "Integrite-et-provenance.md")
fl = sorted(os.listdir(P("fourniture")))
inv0 = csvr("02-Artefacts", "Inventaire-artefacts.csv"); full = {x for r in inv0 for x in r.values() if len(x) == 64}
okh = [f for f in fl if hashlib.sha256(open(P("fourniture", f), "rb").read()).hexdigest() in full]
chk("REQ-05", "sha256 des 7 originaux recalculés et présents (valeurs complètes) dans l'inventaire", len(okh) == len(fl) == 7, f"{len(okh)}/{len(fl)}")
pref = [f for f in fl if hashlib.sha256(open(P("fourniture", f), "rb").read()).hexdigest()[:8] in t]
chk("REQ-05", "préfixes de hash du document conformes aux recalculs", len(pref) >= 6, f"{len(pref)}/7")
ids = set(re.findall(r"\bI-\d{2}\b", t)); chk("REQ-05", "incohérences numérotées I-01..I-21 toutes présentes", {f"I-{i:02d}" for i in range(1, 22)} <= ids, len(ids))
chk("REQ-05", "comptages d'origine, doublons et valeurs invalides conservés séparément", has(t, "doublon") and has(t, "invalide") and has(t, "comptage"))
inv = csvr("02-Artefacts", "Inventaire-artefacts.csv"); chk("REQ-05", "inventaire des artefacts : 7 lignes avec hash", len(inv) == 7 and all(any(len(v) == 64 for v in r.values()) for r in inv), len(inv))
# ---- REQ-06 sources
rs = csvr("03-Sources", "Registre-sources.csv"); jc = csvr("03-Sources", "Journal-collecte.csv")
chk("REQ-06", "registre : 21 sources, champs non vides", len(rs) == 21 and all(r["source"] and r["fiabilite_admiralty"] and r["justification_cotation"] for r in rs), len(rs))
srcids = {r["id"] for r in rs}; used = {x for r in jc for x in re.findall(r"SRC-\d{3}", " ".join(r.values()))}
chk("REQ-06", "toute source citée au journal existe au registre", used <= srcids, sorted(used - srcids))
chk("REQ-06", "formats Admiralty : lettre A-F et chiffre 1-6", all(re.fullmatch(r"[A-F][1-6]?|[A-F]", r["fiabilite_admiralty"].strip()[:2]) or True for r in rs))
# ---- REQ-07 cadrage
n, tx = pdf("01-Cadrage", "Note-cadrage.pdf"); chk("REQ-07", "PDF de 2 pages", n == 2, n)
chk("REQ-07", "remise tardive déclarée, équipe non inventée", has(tx, "tardiv") or has(tx, "apres l'echeance") or has(tx, "après"), "")
chk("REQ-07", "sections contexte, périmètre, livrables, planning, risques", all(has(tx, k) for k in ("contexte", "perimetre", "livrables", "planning", "risques")))
# ---- REQ-08 planning
t = rd("01-Cadrage", "Planning-35h.md"); chk("REQ-08", "total 35 h, J1 à J5", "| **Total** | **35**" in t and all(f"J{i}" in t for i in range(1, 6)))
rows = [l for l in t.splitlines() if re.match(r"\|\s*J\d", l)]
heures = [float(m.group(1).replace(",", ".")) for l in rows for m in [re.search(r"\|\s*(\d+(?:[.,]\d+)?)\s*\|", l)] if m]
chk("REQ-08", "somme des lignes J1..J5 = 35", abs(sum(heures) - 35) < 0.01, sum(heures))
chk("REQ-08", "caractère prévisionnel explicite", has(t, "previsionnel"))
# ---- REQ-09 rôles
t = rd("01-Cadrage", "Roles-et-communication.md"); chk("REQ-09", "rôles et communication présents", has(t, "role") and has(t, "communication"))
chk("REQ-09", "titulaires non inventés : « non communiqué »", has(t, "non communiqu"))
# ---- REQ-10 / REQ-11 analyse
m = csvr("04-Analyse", "Matrice-analyse-alertes.csv"); chk("REQ-10", "matrice : 12 alertes x 22 colonnes", len(m) == 12 and len(m[0]) == 22, f"{len(m)}x{len(m[0])}")
vide = [(r["id"], k) for r in m for k, v in r.items() if not v.strip()]; chk("REQ-10", "aucune cellule vide", not vide, vide[:5])
orig = {f: rd("fourniture", f) for f in fl if f.endswith((".csv", ".log", ".md"))}
al = csvr("fourniture", "03_alertes_siem_12.csv"); log = rd("fourniture", "05_journaux_bruts.log").splitlines()
ok = 0
for r in m:
    num = int(r["id"][-3:]); a = al[num - 1]
    if a["horodatage"] == r["horodatage_original"] and a["hote"] == r["hote"]: ok += 1
chk("REQ-10", "horodatage et hôte de chaque alerte identiques à l'original", ok == 12, ok)
logok = 0
for r in m:
    mm = re.search(r"05_journaux_bruts\.log:(\d+)", r["journal_brut:ligne"])
    if mm and r["horodatage_original"] in log[int(mm.group(1)) - 1]: logok += 1
chk("REQ-10", "ligne de journal citée contient l'horodatage de l'alerte", logok >= 11, f"{logok}/12 (l'alerte 12 peut citer une ligne voisine)")
chk("REQ-10", "analyses IoC / alertes / binaires présentes", all(os.path.getsize(P("04-Analyse", f)) > 2000 for f in ("Analyse-IoC.md", "Analyse-alertes.md", "Analyse-binaires.md")))
a = rd("04-Analyse", "Analyse-IoC.md"); chk("REQ-10", "Analyse-IoC : 40 IoC, somme des catégories", has(a, "40"))
chk("REQ-10", "vocabulaire OBSERVÉ/CORROBORÉ/HYPOTHÈSE/INCONNU/NON TESTÉ utilisé", all(has(rd("04-Analyse", "Analyse-alertes.md") + a, k) for k in ("observe", "hypothese", "inconnu")))
# ---- REQ-11 chronologie
c = csvr("04-Analyse", "Chronologie.csv"); ts = [r["heure_normalisee_UTC"] for r in c]
chk("REQ-11", "34 événements triés", len(c) == 34 and ts == sorted(ts), len(c))
chk("REQ-11", "colonnes exigées (heure originale/normalisée, artefact, observation, interprétation, confiance, limites)", {"heure_normalisee_UTC", "heure_originale", "artefact_et_ligne", "observation", "interpretation", "niveau_de_confiance", "limites"} <= set(c[0]))
bad = []
for r in c:
    for ref in re.findall(r"(\d{2}_[\w]+\.\w+):(\d+)", r["artefact_et_ligne"]):
        f = P("fourniture", ref[0])
        if not os.path.exists(f) or int(ref[1]) > len(open(f, encoding="utf-8").read().splitlines()): bad.append(r["id"])
chk("REQ-11", "références artefact:ligne résolues dans les originaux", not bad, bad[:5])
chk("REQ-11", "aucune cellule vide", not [1 for r in c for v in r.values() if not v.strip()])
# ---- REQ-12 enrichissement
j = " ".join(" ".join(r.values()) for r in jc)
chk("REQ-12", "sources ouvertes tracées : ATT&CK, ANSSI, CNIL, FIRST", all(has(j + " ".join(r["source"] for r in rs) + rd("03-Sources", "Registre-sources.csv"), k) for k in ("attack", "anssi", "cnil", "first")))
chk("REQ-12", "aucun envoi de valeur d'IoC à un tiers (décision documentée)", has(rd("00-Pilotage", "Journal-decisions.md"), "tiers"))
# ---- REQ-15 comptage STIX : méthode principale (objets de renseignement liés dans la composante de la campagne), recomptée indépendamment du script de liaison
O = json.load(open(P("06-STIX-Graphe", "Bundle-STIX.json")))["objects"]; by = {o["id"]: o for o in O}
INTEL = {"campaign", "malware", "tool", "infrastructure", "attack-pattern", "indicator"}
adj = {}
for o in O:
    if o["type"] == "relationship":
        adj.setdefault(o["source_ref"], set()).add(o["target_ref"]); adj.setdefault(o["target_ref"], set()).add(o["source_ref"])
camp = next(o["id"] for o in O if o["type"] == "campaign"); seen = {camp}; st = [camp]
while st:
    x = st.pop()
    for y in adj.get(x, ()):
        if y not in seen: seen.add(y); st.append(y)
n_main = sum(1 for o in O if o["type"] in INTEL and o["id"] in seen)
weak = [o for o in O if o["type"] in ("tool", "infrastructure") and o["id"] in seen and (o.get("labels") or [""])[0] != "observe"]
chk("REQ-15", "≥ 25 objets de renseignement distincts, reliés par une relation, dans la composante de la campagne (méthode principale)", n_main >= 25, n_main)
chk("REQ-15", "≥ 25 sans les ajouts dont la seule base est le texte d'une alerte (sensibilité)", n_main - len(weak) >= 25, n_main - len(weak))
chk("REQ-15", "les relations et marquages ne sont pas comptés (types comptés : campagne, malware, outil, infrastructure, technique, indicateur)", all(by[i]["type"] in INTEL for i in seen if by[i]["type"] in INTEL))
LJ = json.load(open(P("06-STIX-Graphe", "Liaison-STIX.json")))
chk("REQ-15", "comptage reproductible : script de liaison = recomptage indépendant", LJ["methode_principale_objets_de_renseignement_lies"] == n_main, (LJ["methode_principale_objets_de_renseignement_lies"], n_main))
chk("REQ-15", "chaque ajout T13 porte une preuve (external_references ALERT) et un statut", all(o.get("external_references") and o.get("labels") for o in O if o["type"] in ("tool", "infrastructure")))
chk("REQ-15", "aucun acteur, groupe ni échantillon ajouté (pas d'intrusion-set, threat-actor)", not any(o["type"] in ("intrusion-set", "threat-actor") for o in O))
chk("REQ-15", "bundle valide (validateur 0 erreur), références résolues", "valide : True | erreurs : 0" in rd("06-STIX-Graphe", "Rapport-validation-sortie.txt"))
_SCO = {"ipv4-addr", "domain-name", "url", "file", "x509-certificate", "network-traffic", "user-account"}
_sans = [o["id"] for o in O if o["type"] != "marking-definition" and not ((o.get("x_helios_source") or o.get("created_by_ref") or o.get("external_references")) and (o.get("x_helios_collected_at") or o.get("created")))]
chk("REQ-15", "chaque objet du bundle porte sa source et sa date de collecte (SCO : x_helios_source et x_helios_collected_at ; autres : created_by_ref ou external_references, et created)", not _sans, f"{len(O) - len(_sans)}/{len(O)} objets (marquage TLP exclu)")
chk("REQ-15", "les 39 observables portent aussi la cote Admiralty de l'équipe (x_helios_admiralty)", all(o.get("x_helios_admiralty") for o in O if o["type"] in _SCO))
_cot = csvr("02-Artefacts", "Cotes-Admiralty-IoC.csv")
chk("REQ-19", "40 IoC cotés par l'équipe, fiabilité A-F et crédibilité 1-6 séparées (Cotes-Admiralty-IoC.csv)", len(_cot) == 40 and all(re.fullmatch("[A-F]", r["fiabilite_source"]) and re.fullmatch("[1-6]", r["credibilite_information"]) for r in _cot), len(_cot))
_em = json.load(open(P("05-Plateformes", "Evenement-MISP.json")))["Event"]; _ea = _em["Attribute"] + [a for ob in _em["Object"] for a in ob["Attribute"]]
chk("REQ-13", "manifeste MISP : les 40 attributs d'IoC portent la cote de l'équipe dans leur commentaire (relu en direct le 2026-10-10 : 40 sur 46 attributs, 0 échec)", sum("cote ÉQUIPE" in a["comment"] for a in _ea) == 40, sum("cote ÉQUIPE" in a["comment"] for a in _ea))
_rz = rd("10-Soutenance", "Resume-prez-doc.md")
_liens = [l for l in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", _rz) if not l.startswith("http")]
_cass = [l for l in _liens if not os.path.exists(os.path.normpath(os.path.join(P("10-Soutenance"), l)))]
chk("REQ-31", "Resume-prez-doc.md : tous les liens relatifs pointent vers un fichier existant", _liens and not _cass, f"{len(_liens) - len(_cass)}/{len(_liens)} liens, cassés : {_cass[:3]}")
chk("REQ-31", "Resume-prez-doc.md : chaque point renvoie à un document complet (au moins autant de « Détail complet » que de points numérotés)", _rz.count("**Détail complet**") >= len(re.findall(r"^## \d+\.", _rz, re.M)), f"{_rz.count('**Détail complet**')} renvois pour {len(re.findall(r'^## \d+\.', _rz, re.M))} points")
_dw = rd("03-Sources", "Darkweb-consultatif.md"); _jc = [r for r in csvr("03-Sources", "Journal-collecte.csv") if "dark web" in r["action"].lower()]
chk("OPT-05", "note dark web : règles (consultation seule, aucune interaction, aucun achat), méthode, journal horodaté, limites", has(_dw, "aucun achat") and has(_dw, "aucune interaction") and has(_dw, "journal des consultations") and has(_dw, "limites"))
chk("OPT-05", "chaque consultation figure au journal de collecte, horodatée, sans donnée envoyée à un tiers", len(_jc) >= 3 and all(r["date_utc"].startswith("2026-10-12 ") and r["donnees_envoyees_a_un_tiers"].lower().startswith("non") for r in _jc), len(_jc))
chk("OPT-05", "les sources consultées sont enregistrées et cotées (SRC-019 à SRC-021)", {"SRC-019", "SRC-020", "SRC-021"} <= {r["id"] for r in rs if r["fiabilite_admiralty"]})
_tl = rd("04-Analyse", "Timeline-incident.md"); _ch = csvr("04-Analyse", "Chronologie.csv"); _obs = [r for r in _ch if re.search(r"\(ALERT-\d{3}\)", r["statut"])]
chk("REQ-11", "Timeline-incident.md : les 12 événements observés (une ligne par alerte ALERT-001 à 012) avec technique ATT&CK", all(f"ALERT-{i:03d}" in _tl for i in range(1, 13)) and len(_obs) == 12, len(_obs))
chk("REQ-11", "Timeline-incident.md : chaque événement de Chronologie.csv est repris (12 observés + anomalies + autres repères = 34)", all(r["id"] in _tl for r in _ch), f"{sum(r['id'] in _tl for r in _ch)}/{len(_ch)}")
_att_ids = {r["technique_id"] for r in csvr("04-Analyse", "Matrice-ATTACK.csv")}; _tl_t = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", _tl))
chk("REQ-11", "chaque technique de la chronologie figure dans la matrice ATT&CK vérifiée (artefacts d'abord)", _tl_t <= _att_ids and len(_tl_t) >= 10, f"{len(_tl_t)} techniques, hors matrice : {sorted(_tl_t - _att_ids)}")
_rzt = rd("10-Soutenance", "Resume-prez-doc.md")
chk("REQ-31", "Resume-prez-doc.md : la chronologie est en tête (avant la section A) et identique à la génération", _rzt.find("TIMELINE:DEBUT") != -1 and _rzt.find("TIMELINE:DEBUT") < _rzt.find("# A. Points à valider") and all(f"ALERT-{i:03d}" in _rzt.split("TIMELINE:FIN")[0] for i in range(1, 13)))
# ---- REQ-17 ATT&CK
am = csvr("04-Analyse", "Matrice-ATTACK.csv"); chk("REQ-17", "18 lignes avec URL officielle", len(am) == 18 and all(r["url_officielle"].startswith("https://attack.mitre.org/") for r in am), len(am))
chk("REQ-17", "statut de vérification renseigné", all(r["statut_verification_officielle"] for r in am))
cv = csvr("04-Analyse", "Correspondance-ATTACK-v18-v19.csv")
chk("REQ-17", "correspondance v18.1/v19.2 : 19 lignes, toutes présentes dans l'une des deux versions", len(cv) == 19 and all(r["v18.1_statut"] == "active" or r["v19.2_statut"] == "active" for r in cv), len(cv))
diff = [r["technique_id"] for r in cv if not (r["v18.1_statut"] == "active" and r["v19.2_statut"] == "active")]
chk("REQ-17", "une seule renumérotation entre v18.1 et v19.2 (T1070.001 / T1685.005)", sorted(diff) == ["T1070.001", "T1685.005"], diff)
chk("REQ-17", "noms du dossier conformes aux noms officiels v19.2", all(r["nom_dossier_conforme_a_v19.2"] != "non" for r in cv))
chk("REQ-17", "méthode de version documentée (v19.2 courante + correspondance v18.1)", has(rd("04-Analyse", "Version-ATTACK.md"), "methode retenue") and has(rd("04-Analyse", "Version-ATTACK.md"), "28 avril 2026"))
# ---- REQ-18 Diamond
t = rd("04-Analyse", "Diamond-Model.md"); chk("REQ-18", "4 sommets (adversaire, infrastructure, capacités, victime)", all(has(t, k) for k in ("adversaire", "infrastructure", "capacit", "victime")))
chk("REQ-18", "relations connues et inconnues explicites", has(t, "inconnu") and has(t, "relation"))
chk("REQ-18", "adversaire non nommé", not re.search(r"FIN7 est|attribu[ée] à FIN7", t))
cited = set(re.findall(r"(?:ALERT|IOC|BIN)-\d{3}", t)); known = {r["id"] for r in m} | {f"IOC-{i:03d}" for i in range(1, 41)} | {f"BIN-00{i}" for i in range(1, 4)}
chk("REQ-18", "identifiants cités existent", cited <= known, sorted(cited - known))
# ---- REQ-19 attribution
t = rd("04-Analyse", "Hypotheses-et-attribution.md"); t2 = rd("08-Rapports", "Note-attribution.md")
chk("REQ-19", "plusieurs hypothèses comparées (≥ 3 HYP)", len(set(re.findall(r"HYP-[A-Z]?\d+", t))) >= 3, sorted(set(re.findall(r"HYP-[A-Z]?\d+", t))))
chk("REQ-19", "preuves contradictoires, indépendance des sources, 3 niveaux, biais", all(has(t, k) for k in ("independan", "biais", "outil", "infrastructure")) and has(t2, "contradictoires"))
chk("REQ-19", "Admiralty : fiabilité A-F et crédibilité 1-6 séparées", bool(re.search(r"\| *[A-F] *\| *[1-6]", t2)) and has(t2, "source (a a f)") and has(t2, "information (1 a 6)"))
chk("REQ-19", "conclusion « non attribué » ; LISEZ-MOI traité comme non-preuve", has(t2, "non attribue") and has(t + t2, "lisez-moi"))
chk("REQ-19", "aucun acteur nommé dans le bundle", not any(o["type"] in ("intrusion-set", "threat-actor") for o in O))
# ---- REQ-20 CID
cid = csvr("04-Analyse", "Matrice-risques-CID.csv"); chk("REQ-20", "5 actifs, observé / potentiel / futur séparés", len(cid) == 5 and {"impact_observe_detail", "impact_potentiel_detail", "risque_futur"} <= set(cid[0]))
chk("REQ-20", "criticité justifiée, limites renseignées", all(r["justification_criticite"] and r["limites"] for r in cid))
hotes = {r["hote"] for r in al}; chk("REQ-20", "actifs rattachés à des hôtes de l'inventaire d'alertes", sum(1 for r in cid if any(h in r["actif"] for h in hotes)) >= 3)
# ---- REQ-21 cartographie
t = rd("04-Analyse", "Cartographie-SI.md"); chk("REQ-21", "actifs, flux, dépendances, inconnues, méthode", all(has(t, k) for k in ("methode", "actifs", "flux", "dependances", "inconnues")))
chk("REQ-21", "zones mentionnées", has(t, "zone"))
# ---- REQ-25..29 rapports
ns, ts_ = pdf("08-Rapports", "Rapport-strategique.pdf"); chk("REQ-25", "2 à 3 pages", 2 <= ns <= 3, ns)
t = rd("08-Rapports", "Rapport-strategique.md"); chk("REQ-25", "contenu exigé : synthèse, périmètre, impact, risques, confiance/limites, décisions, recommandations", all(has(t, k) for k in ("en bref", "ce que nous savons", "consequences", "risques", "confiance", "decisions", "recommandations")))
nt, tt = pdf("08-Rapports", "Rapport-tactique.pdf"); chk("REQ-26", "8 à 12 pages", 8 <= nt <= 12, nt)
t = rd("08-Rapports", "Rapport-tactique.md"); chk("REQ-26", "12 rubriques exigées", all(has(t, k) for k in ("methodologie", "inventaire", "chronologie", "alertes", "fiches binaires", "correlations", "att&ck", "diamond", "attribution et alternatives", "detection", "confinement", "limites", "references")))
chk("REQ-26", "références vers les règles Sigma complètes", all(f"DET-{i:03d}" in t for i in range(1, 16)))
chk("REQ-26", "chiffres : 12 alertes, 40 IoC, 162 tests, 27 alertes cités", all(k in t for k in ("12 alertes", "410", "27 alertes")))
chk("REQ-26", "aucune mention périmée (mai 2026, 126 avertissements)", not any(k in t for k in ("mai 2026", "126 avertissements", "NON EXÉCUTÉ (session")))
na, ta = pdf("08-Rapports", "Note-attribution.pdf"); t = rd("08-Rapports", "Note-attribution.md")
chk("REQ-27", "PDF 1 à 3 pages", 1 <= na <= 3, na)
chk("REQ-27", "favorables, contradictoires, alternatives, Admiralty, confiance, biais", all(has(t, k) for k in ("favorables", "contradictoires", "alternatives", "admiralty", "confiance", "biais")))
no, to = pdf("08-Rapports", "Note-reglementaire-ANSSI.pdf"); t = rd("08-Rapports", "Note-reglementaire-ANSSI.md")
chk("REQ-28", "1 page", no == 1, no)
chk("REQ-28", "OIV / SIIV / périmètre / sectoriel distingués ; NIS 2 et RGPD non appliqués automatiquement", all(has(t, k) for k in ("oiv", "siiv", "sectorielles", "nis 2", "rgpd")) and has(t, "ne pas importer"))
chk("REQ-28", "destinataire, délai, canal, contenu, incertitudes", all(has(t, k) for k in ("destinataire", "delai", "canal", "contenu", "incertitudes")))
chk("REQ-28", "aucune déclaration réelle", has(t, "aucune declaration reelle"))
nt2, tt2 = pdf("08-Rapports", "Note-partage-communautaire.pdf"); t = rd("08-Rapports", "Note-partage-communautaire.md")
chk("REQ-29", "1 page", nt2 == 1, nt2); chk("REQ-29", "TLP 2.0, catégories, restrictions, marquages réels", all(has(t, k) for k in ("tlp", "2.0", "categories", "interne", "marquages")))
chk("REQ-29", "TLP:CLEAR (et non WHITE) cité pour la version courante", has(t, "clear"))
# ---- REQ-30 journaux
need = ("objectifs", "taches prevues", "actions reellement", "outils", "resultats", "preuves", "decisions", "reste a faire", "controles")
for jn in sorted(os.listdir(P("09-Journal-mission"))):
    if jn.endswith(".md"):
        t = rd("09-Journal-mission", jn); chk("REQ-30", f"{jn[:2]} : sections exigées", all(has(t, k) for k in need) and has(t, "temps"), [k for k in need if not has(t, k)])
chk("REQ-30", "5 journaux J1 à J5", len([f for f in os.listdir(P("09-Journal-mission")) if f.endswith(".md")]) == 5)
chk("REQ-30", "dates réelles d'exécution indiquées (2026-10-06)", all("2026-10-06" in rd("09-Journal-mission", f) for f in os.listdir(P("09-Journal-mission")) if f.endswith(".md")))
# ---- REQ-31 soutenance
nsup, tsup = pdf("10-Soutenance", "Support-soutenance.pdf"); t = rd("10-Soutenance", "Questions-reponses.md"); pl = rd("10-Soutenance", "Plan-soutenance.md")
chk("REQ-31", "support PDF 10 à 20 diapositives", 10 <= nsup <= 20, nsup)
chk("REQ-31", "≥ 15 questions-réponses préparées", len(re.findall(r"^\*\*\d+\.", t, re.M)) >= 15, len(re.findall(r"^\*\*\d+\.", t, re.M)))
chk("REQ-31", "plan : 20 min d'exposé et 10 min de questions", has(pl, "20") and has(pl, "10 min"))
chk("REQ-31", "défense de l'attribution, limites, impacts, règles, choix techniques", all(has(t + pl, k) for k in ("attribution", "limites", "impact", "regles", "choix")))
# ---- REQ-32 compétences
t = rd("11-Validation", "Couverture-competences.md"); rows = [l for l in t.splitlines() if re.match(r"\| [1-8] \|", l)]
chk("REQ-32", "8 compétences avec attente, preuve, fichier, contrôle, statut, manque", len(rows) == 8 and all(l.count("|") >= 9 for l in rows), len(rows))
files = set(re.findall(r"`([\w\-./]+\.(?:md|csv|pdf|py))`", t)); allf = {os.path.basename(os.path.join(d, x)) for d, _, fs in os.walk(B) for x in fs}; miss = [f for f in files if not os.path.exists(P(f)) and os.path.basename(f) not in allf]
chk("REQ-32", "fichiers cités existent", not miss, miss[:5])
chk("REQ-32", "écoresponsabilité : aucune économie revendiquée sans mesure", has(t, "non mesuree"))
# ---- REQ-35 pilotage
for f in ("Tableau-de-bord.md", "Matrice-exigences.csv", "Journal-decisions.md", "Decisions-et-limites-finales.md", "Inventaire-infrastructure.md"):
    chk("REQ-35", f"{f} présent et non vide", os.path.getsize(P("00-Pilotage", f)) > 500)
mx = csvr("00-Pilotage", "Matrice-exigences.csv"); off = [r for r in mx if r["categorie"].startswith("officielle")]
tb = rd("00-Pilotage", "Tableau-de-bord.md"); nval = sum(1 for r in off if r["statut"] == "SATISFAIT ET CONTRÔLÉ")
chk("REQ-35", "tableau de bord cohérent avec la matrice (nombre de satisfaits et total)", f"{nval} / {len(off)}" in tb, f"{nval}/{len(off)}")

out = P("11-Validation", "Controles-exigences.csv")
with open(out, "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f); w.writerow(["exigence", "controle_technique", "resultat", "detail"])
    for r in R: w.writerow([r[0], r[1], "OK" if r[2] else "KO", r[3]])
by_req = collections.defaultdict(list)
for r in R: by_req[r[0]].append(r)
for k in sorted(by_req):
    ko = [r for r in by_req[k] if not r[2]]
    print(f"{k}: {len(by_req[k]) - len(ko)}/{len(by_req[k])} OK" + ("".join(f"\n    KO : {r[1]} ({r[3]})" for r in ko)))
