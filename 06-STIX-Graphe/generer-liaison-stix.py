#!/usr/bin/env python3
"""Comptage reproductible des objets STIX « liés » et inventaire complet du bundle.

Entrées : Bundle-STIX.json, Export-MISP-brut.json, ../02-Artefacts/Inventaire-IoC.csv. Aucune connexion réseau, aucune écriture hors de ce dossier.
Sorties : Inventaire-liaison-STIX.csv (une ligne par objet), Liaison-STIX.json (comptages), Justification-25-objets-lies.md (rapport).
Exécuter : /Users/rapatt/Projet/cti-helios-env/.venv/bin/python 06-STIX-Graphe/generer-liaison-stix.py

MÉTHODE PRINCIPALE (choix de vérification conservateur, PAS une règle imposée par le commanditaire) :
un « objet de renseignement lié » est un objet d'analyse (campaign, malware, tool, infrastructure, attack-pattern, indicator) qui est
l'extrémité d'au moins une RELATION STIX explicite (SRO) et qui appartient à la composante connexe (graphe des SRO) de la campagne.
Ne sont comptés ni les relations, ni les marquages, ni les objets techniques, ni les conteneurs (report, grouping, note, observed-data),
ni les observables (SCO), ni les identités (comptées à part comme actifs victimes)."""
import json, csv, os, collections, re
G = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(G)
O = json.load(open(os.path.join(G, "Bundle-STIX.json"), encoding="utf-8"))["objects"]; by = {o["id"]: o for o in O}
EXP = {o["id"] for o in json.load(open(os.path.join(G, "Export-MISP-brut.json"), encoding="utf-8"))["objects"]}
IOC = list(csv.DictReader(open(os.path.join(BASE, "02-Artefacts", "Inventaire-IoC.csv"), encoding="utf-8")))
SCO = {"file", "domain-name", "ipv4-addr", "url", "x509-certificate", "network-traffic", "user-account"}
INTEL = {"campaign", "malware", "tool", "infrastructure", "attack-pattern", "indicator"}   # objets de renseignement comptés (méthode principale)
LEGACY4 = {"campaign", "malware", "attack-pattern", "indicator"}                          # comptage C d'avant l'ajout T13
CONT = {"report", "grouping", "note"}
T13 = {"tool", "infrastructure"}

def norm(v): return re.sub(r"\[\.\]", ".", str(v).strip().lower()).replace("hxxps", "https").replace("hxxp", "http")
iocv = {}
for k, r in enumerate(IOC, 2):
    iocv[norm(r["valeur_normalisee"])] = (r["id"], k); iocv[norm(r["valeur_originale"])] = (r["id"], k)
def ioc_of(o):
    vals = [o.get("value"), o.get("user_id")] + list((o.get("hashes") or {}).values())
    return [iocv[norm(v)] for v in vals if v and norm(v) in iocv]

def cat(o):
    t = o["type"]
    if t in INTEL: return "analytique"
    if t == "identity": return "identité (actif victime)" if o.get("identity_class") == "system" or o.get("name", "").startswith("Helios") else "identité (auteur)"
    if t in SCO: return "observable (SCO)"
    if t == "observed-data": return "observed-data (conteneur d'observation)"
    if t in CONT: return "conteneur"
    if t == "relationship": return "relation"
    return "marquage ou objet technique"

# ------------------------------------------------------------------ références
def refs(o):
    out = []
    for k, v in o.items():
        if k.endswith("_ref") and isinstance(v, str): out.append((k, v))
        elif k.endswith("_refs") and isinstance(v, list): out += [(k, x) for x in v if isinstance(x, str)]
    return out
sro_out = collections.defaultdict(list); sro_in = collections.defaultdict(list); oth_out = collections.defaultdict(list); oth_in = collections.defaultdict(list)
adj = collections.defaultdict(set)
for o in O:
    if o["type"] == "relationship":
        s, t = o["source_ref"], o["target_ref"]
        sro_out[s].append((o["relationship_type"], t, o.get("labels", [""])[0])); sro_in[t].append((o["relationship_type"], s, o.get("labels", [""])[0])); adj[s].add(t); adj[t].add(s)
    else:
        for k, t in refs(o):
            if t in by and k not in ("created_by_ref", "object_marking_refs"): oth_out[o["id"]].append((k, t)); oth_in[t].append((k, o["id"]))
comp = {}; n = 0
for s0 in list(adj):
    if s0 in comp: continue
    n += 1; st = [s0]
    while st:
        x = st.pop()
        if x in comp: continue
        comp[x] = n; st += list(adj[x])
camp = next(o for o in O if o["type"] == "campaign"); CC = comp[camp["id"]]

def label_of(o): return (o.get("labels") or [""])[0]
def nm(o):
    t = o["type"]
    if t == "relationship": return f"{o['relationship_type']} : {by[o['source_ref']]['type']} -> {by[o['target_ref']]['type']}"
    for k in ("name", "value", "user_id"):
        if k in o: return str(o[k])
    if "hashes" in o: return "; ".join(f"{a}={b[:16]}…" for a, b in o["hashes"].items() if a in ("SHA-256", "SHA-1"))
    if t == "observed-data": return "observation de " + ", ".join(by[r]["type"] for r in o.get("object_refs", [])[:3])
    if t == "network-traffic": return f"trafic vers {by[o['dst_ref']].get('value', '?')}:{o.get('dst_port', '?')}"
    return o.get("abstract", "")[:60] or t

def source_of(o):
    t = o["type"]
    ers = [e.get("description", "") for e in o.get("external_references", []) if e.get("source_name", "").startswith("Dossier")]
    txt = " ".join(ers); a = []
    for m in re.findall(r"ALERT-0*(\d+)", txt): a.append(f"fourniture/03_alertes_siem_12.csv alerte {int(m)}")
    for m in re.findall(r"journal (?:ligne|lignes) (\d+)", txt): a.append(f"fourniture/05_journaux_bruts.log ligne {m}")
    if re.search(r"fiche", txt): a.append("fourniture/01_fiches_analyse_binaires.md")
    for m in re.findall(r"IOC-\d+", txt): a.append(f"fourniture/02_indicateurs_40.csv ({m})")
    if t in SCO:
        i = ioc_of(o)
        if i: a += [f"fourniture/02_indicateurs_40.csv ligne {l} ({x})" for x, l in sorted(set(i))]
        elif t == "network-traffic": a.append("fourniture/05_journaux_bruts.log (trafic Zeek ou Squid)")
    if t == "observed-data":
        for r in o.get("object_refs", []):
            i = ioc_of(by[r]); a += [f"fourniture/02_indicateurs_40.csv ({x})" for x, l in i]
    if t == "identity" and cat(o).endswith("victime)"): a.append("énoncé du sujet (victime) ; hôtes cités par les alertes et le journal brut")
    if t == "attack-pattern":
        tid = [e["external_id"] for e in o["external_references"] if e["source_name"] == "mitre-attack"][0]; a.append(f"technique {tid} : https://attack.mitre.org (vérifiée, voir 04-Analyse/Version-ATTACK.md)")
    return " ; ".join(dict.fromkeys(a)) or "synthèse de l'équipe (aucun artefact unique)"

def provenance(o):
    if o["id"] in EXP: return "export MISP réel (événement 6)"
    if o["type"] in SCO and o["type"] == "user-account": return "conversion locale d'un attribut MISP (T6)"
    return "enrichissement local T13 (2026-10-07)" if o["type"] in T13 else "enrichissement local documenté (T3 à T5)"
def obs_date(o):
    for k in ("first_observed", "first_seen", "valid_from"):
        if o.get(k): return o[k]
    return ""

# ------------------------------------------------------------------ comptages
intel = [o for o in O if o["type"] in INTEL]
counted = [o for o in intel if o["id"] in sro_out or o["id"] in sro_in]
in_comp = [o for o in counted if comp.get(o["id"]) == CC]
victims = [o for o in O if cat(o) == "identité (actif victime)" and o["id"] in comp and comp[o["id"]] == CC]
legacy_c = [o for o in in_comp if o["type"] in LEGACY4]
weak_t13 = [o for o in in_comp if o["type"] in T13 and label_of(o) != "observe"]
robust = [o for o in in_comp if o not in weak_t13]
ends = {x for o in O if o["type"] == "relationship" for x in (o["source_ref"], o["target_ref"])}
def_A = [i for i in ends if by[i]["type"] != "relationship"]
def_D = [o for o in O if o["type"] not in ("relationship", "marking-definition") and (o["id"] in ends or oth_out[o["id"]] or oth_in[o["id"]]) and any(k not in ("created_by_ref",) for k, _ in oth_out[o["id"]] + oth_in[o["id"]] + [("", "")] if k) or o["id"] in ends]
def_D = [o for o in O if o["type"] not in ("relationship", "marking-definition") and (o["id"] in ends or any(k != "created_by_ref" for k, _ in oth_out[o["id"]] + oth_in[o["id"]]))]
by_status = collections.Counter(label_of(o) or "n/a" for o in in_comp)
by_type = collections.Counter(o["type"] for o in in_comp)
cats = collections.Counter(cat(o) for o in O)
res = {"objets_total": len(O), "composante_de_la_campagne_taille": sum(1 for v in comp.values() if v == CC), "nombre_de_composantes": n,
       "methode_principale_objets_de_renseignement_lies": len(in_comp), "par_type": dict(by_type), "par_statut": dict(by_status),
       "toutes_dans_la_composante_de_la_campagne": len(in_comp) == len(counted),
       "avec_actifs_victimes": len(in_comp) + len(victims), "actifs_victimes": len(victims),
       "avant_T13_methode_C_4_types": len(legacy_c), "sensibilite_sans_objets_T13_non_observes": len(robust), "objets_T13_non_observes": [o["name"] for o in weak_t13],
       "def_A_extremite_SRO": len(def_A), "def_D_toute_reference": len(def_D), "par_categorie_bundle": dict(cats)}
json.dump(res, open(os.path.join(G, "Liaison-STIX.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)

# ------------------------------------------------------------------ inventaire CSV
def fmt_rel(lst, dirn):
    return " ; ".join(f"{rt} {'->' if dirn == 'o' else '<-'} {by[x]['type']} {nm(by[x])[:40]} [{lab}]" for rt, x, lab in lst)
rows = []
for o in O:
    i, t = o["id"], o["type"]; c = cat(o)
    counted_p = o in in_comp
    if counted_p: why = "compté : objet de renseignement, extrémité d'une relation, dans la composante de la campagne"
    elif t in INTEL: why = "NON compté : aucune relation explicite" if o["id"] not in comp else "NON compté : hors de la composante de la campagne"
    elif c == "identité (actif victime)": why = "compté à part (actif victime) : relié par `targets`, pas dans la méthode principale"
    elif c == "relation": why = "relation : jamais comptée comme entité"
    elif t in SCO: why = "observable : jamais compté comme objet de renseignement"
    else: why = "conteneur, marquage ou objet technique : non compté"
    rows.append([i, t, nm(o), c, label_of(o), source_of(o), provenance(o), "dossier déposé le 2026-09-23 ; acquis et analysé le 2026-10-06", obs_date(o) or o.get("created", ""),
                 fmt_rel(sro_out[i], "o"), fmt_rel(sro_in[i], "i"), len(oth_out[i]), "; ".join(sorted({by[x]["type"] for _, x in oth_in[i]})),
                 comp.get(i, ""), "oui" if counted_p else "non", why])
with open(os.path.join(G, "Inventaire-liaison-STIX.csv"), "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f); w.writerow(["id", "type", "nom_ou_valeur", "categorie", "statut_analytique", "artefact_source", "provenance", "date_collecte", "date_observation_ou_creation",
                                   "relations_sortantes", "relations_entrantes", "autres_references_sortantes", "referenceurs_entrants", "composante_SRO", "compte_methode_principale", "justification"]); w.writerows(rows)

# ------------------------------------------------------------------ rapport Markdown
def tab(objs, extra=None):
    s = "| Identifiant | Type | Nom | Statut | Source dans les artefacts | Relations |\n|---|---|---|---|---|---|\n"
    for o in sorted(objs, key=lambda x: (x["type"], nm(x))):
        r = len(sro_out[o["id"]]) + len(sro_in[o["id"]])
        s += f"| `{o['id'][:22]}…` | {o['type']} | {nm(o)[:70].replace('|', '/')} | {label_of(o) or 'n/a'} | {source_of(o)[:150]} | {r} |\n"
    return s + "\n"
nrel = sum(1 for o in O if o["type"] == "relationship"); nsco = cats["observable (SCO)"]
rels_by = collections.Counter(o["relationship_type"] for o in O if o["type"] == "relationship")
md = f"""# Justification : au moins 25 objets STIX liés

Généré par `06-STIX-Graphe/generer-liaison-stix.py` depuis `Bundle-STIX.json` ({len(O)} objets). Inventaire ligne à ligne : `Inventaire-liaison-STIX.csv`. **Cette méthode est un choix de vérification conservateur de l'équipe, pas une règle imposée par le commanditaire** ; la définition de « objets liés » n'a pas été fournie (RFI-05).

## 1. Résultat

**{len(in_comp)} objets de renseignement distincts, tous reliés dans une seule composante connexe** (celle de la campagne « cluster non attribué », {res['composante_de_la_campagne_taille']} objets au total avec les observables, identités et données observées atteints par une relation). Seuil de 25 : **{'ATTEINT' if len(in_comp) >= 25 else 'NON ATTEINT'}**. Sensibilité : en retirant les {len(weak_t13)} objets ajoutés dont la seule base est le texte d'une alerte (statut hypothèse ou déclaré), il en reste **{len(robust)}** ({'seuil toujours atteint' if len(robust) >= 25 else 'seuil non atteint'}). En ajoutant les {len(victims)} actifs victimes (comptés à part) : {len(in_comp) + len(victims)}.

| Catégorie (jamais mélangées) | Nombre | Dans le comptage ? |
|---|---|---|
| **Objets de renseignement** : {', '.join(f'{k} {v}' for k, v in sorted(by_type.items()))} | **{len(in_comp)}** | **oui** |
| Actifs victimes (identités : organisation et 3 systèmes) | {len(victims)} | non (comptés à part) |
| Observables (SCO) | {nsco} | non |
| Données observées (conteneurs d'observation) | {cats['observed-data (conteneur d\'observation)']} | non |
| Relations ({', '.join(f'{k} {v}' for k, v in sorted(rels_by.items()))}) | {nrel} | **jamais comptées comme entités** |
| Conteneurs (rapport, regroupement, notes) | {cats['conteneur']} | non |
| Identités d'auteur, marquage, objets techniques | {cats['identité (auteur)'] + cats['marquage ou objet technique']} | non |

Statuts des {len(in_comp)} objets comptés : {', '.join(f'{k} {v}' for k, v in sorted(by_status.items()))} (le statut est écrit dans chaque objet : un objet « hypothèse » ou « déclaré » est un objet de renseignement étiqueté comme tel, pas une observation).

## 2. Pourquoi 20, 24, 34, 99 (avant les ajouts), et 27 maintenant

| Comptage | Définition | Avant T13 | Après T13 |
|---|---|---|---|
| **Principal (M)** | objets de renseignement (campagne, malware, outil, infrastructure, technique, indicateur) extrémités d'une relation, dans la composante de la campagne | n/a | **{len(in_comp)}** |
| C (ancienne définition conservatrice) | mêmes types sans `tool` ni `infrastructure` | 20 | {len(legacy_c)} |
| B | C et les 4 actifs victimes | 24 | {len(legacy_c) + len(victims)} |
| A | tout objet (hors relation) extrémité d'une relation (ajoute observables et données observées reliés) | 34 | {len(def_A)} |
| D | A et tout objet référencé par un conteneur ou une donnée observée (hors relations et marquage) | 99 | {len(def_D)} |

Les écarts viennent des objets réels : A ajoute à B les observables atteints par un `based-on` ou un `consists-of` et les données observées reliées ; D ajoute tout ce que le rapport, le regroupement, les notes et les données observées référencent. **Les relations et marquages ne sont jamais comptés comme entités** dans la méthode principale.

## 3. Ajouts T13 (2026-10-07) : preuve et justification

Les 20 objets d'analyse d'origine étaient justifiés par les alertes et fiches (voir leurs lignes ci-dessous). Une recherche des éléments prouvés mais omis a donné **7 ajouts**, chacun relié à la campagne ; **aucun malware, acteur ou échantillon n'a été ajouté**, aucun découpage artificiel (un objet par rôle ou par logiciel distinct cité).

| Ajout | Preuve | Statut | Pourquoi ce n'est pas un doublon |
|---|---|---|---|
| tool `powershell.exe` | journal brut ligne 1 : `winword.exe -> powershell.exe -enc ... -w hidden` (alerte 1) | observé | la technique T1059.001 décrit un comportement ; l'outil est le logiciel nommé dans la ligne de commande |
| tool `wevtutil.exe` | journal brut ligne 12 : `1102 audit log cleared / wevtutil cl Security` (alerte 12) | observé | idem pour T1685.005 |
| tool `schtasks.exe` | détail de l'alerte 3 seulement (`schtasks /create`) ; **absent du journal brut (I-20)** | déclaré | idem pour T1053.005 |
| infrastructure : hébergement du téléchargement (cdn-svc-update.test) | alerte 2, journal ligne 2 : GET 200 de 421376 octets ; IOC-013, IOC-029 | observé | un rôle réseau (hôte de la seconde charge), distinct de l'indicateur qui n'est qu'un motif de détection |
| infrastructure : destination de la balise (198.51.100.24) | alerte 4, journal ligne 4 : une connexion vers :443 ; IOC-020 | observé (périodicité non démontrée) | idem pour le rôle de balise |
| infrastructure : destination de la sortie (203.0.113.28) | alerte 10, journal ligne 10 : 2 469 135 790 octets vers :8080 ; IOC-024 | observé | idem pour la sortie de données |
| infrastructure : repli supposé (static-assets-cache.test) | alerte 11, journal ligne 11 ; **rôle contredit par I-11** | hypothèse | rôle de repli distinct des trois autres ; étiqueté hypothèse |

Relations ajoutées : {sum(1 for o in O if o['type'] == 'relationship' and by[o['target_ref']]['type'] in T13)} `uses` depuis la campagne (3 outils, 4 infrastructures) et {rels_by['consists-of']} `consists-of` de chaque infrastructure vers les observables déjà présents (domaines, URL, adresses). Aucune relation n'a été créée pour l'apparence : chacune dit un fait ou une hypothèse étiquetée prouvé par la ligne citée. Les 4 infrastructures ne reprennent pas les relations `indicates` des indicateurs (elles ne sont pas démontrées par un artefact).

**Éléments cherchés et NON ajoutés, faute de preuve** : les techniques seulement probables (T1003.001, T1071.001, T1008, T1048.003, T1136.002, T1078, T1543.003) ; un `intrusion-set` ou une famille de malware (aucun élément indépendant) ; des indicateurs pour les 32 autres IoC déclarés non vérifiés ; `rundll32.exe` (le processus hôte de la DLL n'est pas nommé, I-08) ; `explorer.exe` (cible d'injection, pas un outil de l'attaquant) ; des `course-of-action` (recommandations de l'équipe, pas des faits des artefacts).

## 4. Les {len(in_comp)} objets comptés et leurs preuves

{tab(in_comp)}
## 5. Actifs victimes (comptés à part)

{tab(victims)}
## 6. Objets exclus du comptage principal, et pourquoi

| Catégorie | Nombre | Exemple | Pourquoi exclus |
|---|---|---|---|
| Observables (SCO) | {nsco} | adresses, domaines, URL, hashes de fichier | des valeurs, pas des objets d'analyse ; atteints par `based-on` et `consists-of` |
| Données observées | {cats['observed-data (conteneur d\'observation)']} | observation d'un fichier ou d'un domaine | conteneurs d'observation |
| Relations | {nrel} | `uses`, `targets`, `indicates`, `based-on`, `consists-of`, `related-to` | jamais des entités |
| Conteneurs, identités d'auteur, marquage | {cats['conteneur'] + cats['identité (auteur)'] + cats['marquage ou objet technique']} | rapport, regroupement, 5 notes, 2 identités d'auteur, TLP | techniques ou documentaires |

Détail objet par objet (types, relations entrantes et sortantes, autres références, composante, inclusion et justification) : `Inventaire-liaison-STIX.csv`.

## 7. Procédure reproductible de comptage

1. `bash 11-Validation/regenerer-stix.sh` (construit le bundle, le valide, génère le graphe, l'inventaire et ce document) ou, pour le seul comptage : `/Users/rapatt/Projet/cti-helios-env/.venv/bin/python 06-STIX-Graphe/generer-liaison-stix.py`.
2. Le script lit `Bundle-STIX.json`, construit le graphe non orienté des relations (`relationship`), prend la composante de la campagne et retient les objets de type campaign, malware, tool, infrastructure, attack-pattern et indicator qui y figurent.
3. Contrôle : `11-Validation/controles-exigences.py` (REQ-15) recompte indépendamment depuis le bundle et compare à `Liaison-STIX.json`.
4. Équivalent à la main : `jq '[.objects[] | select(.type|IN("campaign","malware","tool","infrastructure","attack-pattern","indicator"))] | length' Bundle-STIX.json` donne {len(intel)} objets de ces types ; tous sont reliés par au moins une relation et appartiennent à la composante de la campagne ({'oui' if len(in_comp) == len(intel) else 'non : voir l\'inventaire'}).

## 8. Cohérence avec MISP et OpenCTI, et corrections externes

| Plateforme | État | Correction préparée |
|---|---|---|
| MISP | l'événement 6 ne contient ni `tool` ni `infrastructure` (aucun type de ce nom dans le modèle d'objets utilisé) ; les objets d'analyse (campagne, malwares, indicateurs, techniques sous forme de galaxies) n'y sont déjà que partiellement | **aucune** : écart documenté (`Ecarts-bundle-plateformes.md`, E12) |
| OpenCTI | l'incident remplace la campagne ; ni infrastructure ni outil | création de 4 `Infrastructure` et liaison à 3 outils existants : préparée dans `05-Plateformes/octi_stix_complements.py` (mode plan en lecture seule), **non appliquée sans approbation** |

## 9. Limites

La méthode compte des objets de statuts différents (observé, déclaré, hypothèse) : elle démontre 25 objets de renseignement justifiés et étiquetés, pas 25 observations. La définition de « lié » n'a pas été confirmée par le commanditaire. Le bundle reste dérivé de l'export MISP et enrichi localement, pas un export pur. Les ajouts T13 existent dans le bundle ; leur présence dans OpenCTI dépend d'une approbation.
"""
open(os.path.join(G, "Justification-25-objets-lies.md"), "w", encoding="utf-8").write(md)
print(json.dumps({k: res[k] for k in ("methode_principale_objets_de_renseignement_lies", "par_type", "par_statut", "toutes_dans_la_composante_de_la_campagne", "avec_actifs_victimes", "avant_T13_methode_C_4_types", "sensibilite_sans_objets_T13_non_observes", "def_A_extremite_SRO", "def_D_toute_reference", "nombre_de_composantes")}, ensure_ascii=False))
