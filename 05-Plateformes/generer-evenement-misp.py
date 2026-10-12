#!/usr/bin/env python3
"""Génère Evenement-MISP.json (format d'import de l'API MISP /events/add) depuis l'inventaire.

Aucune connexion réseau. Les choix de modélisation sont ceux de l'analyse finale :
- to_ids = false partout (valeurs fictives, aucun export de détection) ;
- aucun attribut IoC dont la nature est INCONNUE n'est qualifié offensif (IOC-025, 026, 028 marqués en commentaire) ;
- les empreintes des fiches binaires vivent dans des objets `file` (pas en doublon d'attributs) ;
- aucune galaxie d'acteur ; galaxies ATT&CK ajoutées par le script d'ingestion pour les techniques OBSERVEES seulement.
"""
import csv, json, os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ioc = {r["id"]: r for r in csv.DictReader(open(os.path.join(BASE, "02-Artefacts", "Inventaire-IoC.csv"), encoding="utf-8"))}
COTE = {r["id"]: r for r in csv.DictReader(open(os.path.join(BASE, "02-Artefacts", "Cotes-Admiralty-IoC.csv"), encoding="utf-8"))}
G = lambda i: ioc[f"IOC-{i:03d}"]
V = lambda i: G(i)["valeur_normalisee"]
FS = lambda i: G(i)["date_evenement_premiere_vue"]

NOTE = {25: "NATURE INCONNUE (IP publique source d'un balayage interne, I-05 ; hypothèse pseudonymisation HYP-003)",
        26: "SOURCE RDP INCONNUE (alerte : interne ; IoC : externe, I-04)",
        28: "non vérifiable (rapport public non fourni, cote D4)", 35: "pivot vers une campagne antérieure non fournie (cote C4)"}

def comment(i, extra=""):
    g = G(i)
    adm = g["admiralty_fournie_SOC"]
    base = f"{g['id']} | dossier fourniture/02_indicateurs_40.csv {g['emplacement']} | première vue {FS(i)} (date de découverte, pas heure d'événement) | cote SOC {adm} (reprise telle quelle) | cote ÉQUIPE admiralty-scale:source-reliability={COTE[g['id']]['fiabilite_source']} admiralty-scale:information-credibility={COTE[g['id']]['credibilite_information']} ({COTE[g['id']]['cote_equipe']}) | contexte source : {g['contexte_original']}"
    n = NOTE.get(i, "")
    return " | ".join(x for x in (base, extra, n, "NON VERIFIE") if x)

def attr(i, typ, cat, value=None, extra="", **kw):
    a = {"type": typ, "category": cat, "value": value if value is not None else V(i), "to_ids": False,
         "comment": comment(i, extra), "first_seen": FS(i), "distribution": "5"}
    a.update(kw)
    return a

def fobj(name_id, filename, size, md5, sha1, sha256, iocs, rem):
    mk = lambda rel, typ, val, cat="Payload delivery": {"object_relation": rel, "type": typ, "value": val, "category": cat, "to_ids": False, "distribution": "5",
                                                      "comment": f"{name_id} ({', '.join(f'IOC-{x:03d}' for x in iocs)}) | fiche 01_fiches_analyse_binaires.md | {rem}"}
    return {"name": "file", "meta-category": "file", "comment": f"{name_id} : empreintes DECLAREES par la fiche ; échantillon NON FOURNI ; aucun contenu binaire", "distribution": "5",
            "Attribute": [mk("filename", "filename", filename), mk("size-in-bytes", "size-in-bytes", str(size)), mk("md5", "md5", md5), mk("sha1", "sha1", sha1), mk("sha256", "sha256", sha256)],
            "_ref_id": name_id}

def dobj(dom, ip, rem):
    mk = lambda rel, typ, val, i: {"object_relation": rel, "type": typ, "value": val, "category": "Network activity", "to_ids": False, "distribution": "5",
                                   "comment": f"{G(i)['id']} | {G(i)['contexte_original']} | {rem}"}
    return {"name": "domain-ip", "meta-category": "network", "comment": "résolution DECLAREE par le SOC, non vérifiée", "distribution": "5",
            "Attribute": [mk("domain", "domain", V(dom), dom), mk("ip", "ip-dst", V(ip), ip)]}

objects = [
    fobj("BIN-001", "facture_mars_2026.xlsm", 68242, V(3), V(2), V(1), [1, 2, 3], "dropper selon la fiche"),
    fobj("BIN-002", "svchost_update.exe", 421376, V(6), V(5), V(4), [4, 5, 6], "balise selon la fiche ; taille corroborée par journal Squid ligne 2"),
    fobj("BIN-003", "rundll32_helper.dll", 210944, V(9), V(8), V(7), [7, 8, 9], "outil d'identifiants selon la fiche, outil générique"),
    dobj(13, 19, "domaine de téléchargement"), dobj(14, 20, "domaine de commande déclaré"),
]
attrs = [
    attr(10, "sha256", "Artifacts dropped", extra="charge PowerShell déchiffrée DECLAREE, aucune capture"),
    attr(11, "sha256", "Artifacts dropped", extra="module injecté DECLARE rattaché à BIN-002 par le SOC, non corroboré"),
    attr(12, "sha256", "Artifacts dropped", extra="archive chiffrée DECLAREE"),
]
for i in (15, 16, 17, 18):
    attrs.append(attr(i, "domain", "Network activity", extra="domaine en .test (non résolvable)"))
for i in (21, 22, 23, 24, 25, 26, 27, 28):
    attrs.append(attr(i, "ip-dst", "Network activity", extra="plage de documentation RFC 5737"))
for i in (29, 30, 31, 32):
    attrs.append(attr(i, "url", "Network activity", extra="URL en .test"))
for i in (33, 34, 35):
    attrs.append(attr(i, "x509-fingerprint-sha1", "Network activity", value=V(i), extra="empreinte seule, aucun certificat fourni"))
attrs += [
    attr(36, "text", "Persistence mechanism", extra="nom de tâche planifiée (aucun type MISP dédié)"),
    attr(37, "text", "Persistence mechanism", extra="compte du SI victime ; créé selon 4720 le 2026-03-05 mais utilisé le 2026-03-04 (I-03)"),
    attr(38, "text", "Persistence mechanism", value=G(38)["valeur_originale"], extra="clé de registre : valeur TRONQUEE dans la source, stockée en texte, pas en regkey"),
    attr(39, "filename", "Artifacts dropped", value=G(39)["valeur_originale"], extra="chemin de fichier temporaire"),
    attr(40, "hostname", "Targeting data", extra="ACTIF VICTIME, pas un IoC offensif"),
]

# attributs d'objets : chaque empreinte ou domaine/IP porte la cote de l'équipe de son IoC (même format que les attributs de premier niveau)
_BYVAL = {r["valeur_normalisee"].lower(): r for r in COTE.values()}
for _o in objects:
    for _a in _o["Attribute"]:
        _r = _BYVAL.get(_a["value"].lower())
        if _r and "cote ÉQUIPE" not in _a["comment"]:
            _a["comment"] += f" | {_r['id']} cote ÉQUIPE admiralty-scale:source-reliability={_r['fiabilite_source']} admiralty-scale:information-credibility={_r['credibilite_information']} ({_r['cote_equipe']})"

event = {"Event": {
    "info": "[CHALLENGE FICTIF] Helios Energy INC-2026-0302",
    "date": "2026-03-02", "distribution": "0", "threat_level_id": "4", "analysis": "1", "published": False,
    "Tag": [{"name": "tlp:amber"}, {"name": "challenge:helios-fictif"}, {"name": "challenge:source=dossier-pedagogique"}],
    "Attribute": attrs, "Object": objects,
}}
extra = {
    "relations": [
        {"de": "BIN-002", "type": "downloaded-from", "vers_valeur": V(29), "commentaire": "taille 421376 identique entre fiche et journal Squid (corroboration), pas de lien de hash"},
    ],
    "galaxies_attack_observees": ["T1059.001", "T1564.003", "T1105", "T1053.005", "T1046", "T1021.001", "T1055", "T1070.001"],
    "galaxies_exclues": {"T1055.012": "contestée (hollowing non démontré)", "T1543.003": "écartée (compte, pas service)",
                         "T1003.001, T1071.001, T1008, T1048.003, T1136.002, T1078": "probables seulement : décrites, non étiquetées", "acteur/groupe": "aucune galaxie d'acteur : attribution non établie"},
    "rapport_evenement": "Synthèse provisoire : voir 08-Rapports et 04-Analyse (aucune attribution)",
}
out = dict(event)
out["_hors_api"] = extra
json.dump(out, open(os.path.join(BASE, "05-Plateformes", "Evenement-MISP.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
n_att = len(attrs) + sum(len(o["Attribute"]) for o in objects)
print(f"événement MISP : {len(attrs)} attributs + {len(objects)} objets ({n_att} attributs au total)")
