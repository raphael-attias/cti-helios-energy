#!/usr/bin/env python3
"""Génère Manifeste-ingestion.json (PROPOSITION, rien n'est écrit dans une plateforme).

Source : 02-Artefacts/Inventaire-IoC.csv. Aucune connexion réseau.
Relancer : python3 05-Plateformes/generer-manifeste.py
"""
import csv, json, os, hashlib

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rows = list(csv.DictReader(open(os.path.join(BASE, "02-Artefacts", "Inventaire-IoC.csv"), encoding="utf-8")))

# type source -> (type MISP, catégorie MISP, to_ids proposé, remarque)
def mapping(r):
    t, ctx, norm = r["type"], r["contexte_original"], r["valeur_normalisee"]
    if t in ("sha256", "sha1", "md5"):
        derived = not ctx.startswith("BIN-0")
        return (t, "Payload delivery" if not derived else "Artifacts dropped", False,
                "empreinte dérivée (charge en mémoire/archive), pas un fichier fourni" if derived else "empreinte déclarée par la fiche, échantillon non fourni")
    if t == "domain":
        return ("domain", "Network activity", False, "domaine de la plage .test, non résolvable")
    if t == "ipv4":
        return ("ip-dst", "Network activity", False, "plage de documentation RFC 5737")
    if t == "url":
        return ("url", "Network activity", False, "URL en .test")
    if t == "sha1-cert":
        return ("x509-fingerprint-sha1", "Network activity", False, "empreinte de certificat")
    # host : 36 tâche planifiée, 37 compte, 38 clé de registre, 39 fichier, 40 poste victime
    n = int(r["id"][-3:])
    if n == 38:
        return ("regkey", "Persistence mechanism", False, "clé du registre (valeur tronquée dans la source : '...')")
    if n == 39:
        return ("filename", "Artifacts dropped", False, "chemin de fichier temporaire")
    if n == 40:
        return ("hostname", "Targeting data", False, "actif VICTIME, pas un IoC : ne doit pas alimenter de détection")
    return ("other", "Persistence mechanism" if n == 36 else "Persistence mechanism", False,
            "nom de tâche planifiée" if n == 36 else "compte de service créé puis supprimé (chronologie incohérente, voir I-03)")

attrs = []
for r in rows:
    mt, cat, ids, rem = mapping(r)
    attrs.append({
        "id_local": r["id"], "type": mt, "category": cat, "value": r["valeur_normalisee"] if mt != "other" else r["valeur_originale"],
        "to_ids": ids, "comment": f"{r['id']} | source SOC | première vue {r['date_evenement_premiere_vue']} | {r['contexte_original']} | {rem}",
        "first_seen": r["date_evenement_premiere_vue"],
        "tags_proposes": [f"admiralty-scale:source-reliability=\"{r['admiralty_fournie_SOC'][0].lower()}\"",
                          f"admiralty-scale:information-credibility=\"{r['admiralty_fournie_SOC'][1]}\""],
        "note_cotation": "cote reprise telle que fournie par le SOC ; évaluation propre à produire (REQ-19)",
    })

manifest = {
    "statut": "PROPOSITION : NON APPROUVE, NON EXECUTE",
    "genere_depuis": "02-Artefacts/Inventaire-IoC.csv",
    "sha256_inventaire": hashlib.sha256(open(os.path.join(BASE, "02-Artefacts", "Inventaire-IoC.csv"), "rb").read()).hexdigest(),
    "cible": {"plateforme": "MISP", "url": "https://172.16.208.253", "instance_verifiee_en_ecriture": False,
              "compte": "A DEFINIR (B-02)", "organisation": "A DEFINIR (B-03)"},
    "evenement": {
        "info": "[CHALLENGE FICTIF] Helios Energy INC-2026-0302",
        "distribution": "0 (cette organisation seulement)", "sharing_group": None,
        "published": False, "analysis": "0 (initial)", "threat_level_id": "2 (moyen) à confirmer",
        "date": "2026-03-02",
        "tags_proposes": ["tlp:amber", "challenge:helios-energy (étiquette locale à créer, à vérifier avant)"],
        "galaxies": "AUCUNE à ce stade : pas de galaxie d'acteur (attribution = hypothèse non établie). Les galaxies ATT&CK 'attack-pattern' ne seront ajoutées qu'après vérification des techniques sur la source officielle (REQ-17).",
    },
    "regles": [
        "to_ids=false pour tous les attributs : les valeurs sont fictives et ne doivent pas nourrir des exports de détection",
        "aucun attribut ne doit être publié ; pas de synchronisation vers un autre MISP",
        "anti-doublon : avant écriture, recherche par valeur dans l'événement cible ; en cas de relance, ne créer que ce qui manque",
        "ISOLATION NON PROUVEE : distribution 0 et événement non publié ne garantissent pas l'absence d'import par les connecteurs (OpenCTI, TheHive). Écriture suspendue tant que la configuration réelle des filtres n'a pas été lue (B-03, Q2)",
        "après écriture éventuelle : relecture d'OpenCTI sur deux cycles de synchronisation pour constater l'absence d'importation",
        "après écriture : relecture de chaque attribut via l'API et comparaison à ce manifeste (Verification-MISP.md)",
    ],
    "objets_proposes": [
        {"template": "file", "pour": ["BIN-001", "BIN-002", "BIN-003"],
         "champs": ["filename", "md5", "sha1", "sha256", "size-in-bytes"],
         "remarque": "relation 'drops' / 'downloads' à ne poser que si la fiche l'établit ; échantillons non fournis"},
        {"template": "domain-ip", "pour": "paires domaine/IP dont la résolution est écrite dans le contexte source (IOC-013/019, IOC-014/020)",
         "remarque": "la résolution est une affirmation de la source, pas une vérification"},
    ],
    "attributs": attrs,
    "hors_perimetre_mis_en_attente": [
        "IOC-028 et IOC-035 : renvoient à des sources non fournies (cotes D4 et C4) ; ingérer avec commentaire 'non confirmé'",
        "alertes SIEM, chronologie, techniques ATT&CK : à apporter plus tard sous forme de commentaires/objets, pas d'IoC",
    ],
}
json.dump(manifest, open(os.path.join(BASE, "05-Plateformes", "Manifeste-ingestion.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print("manifeste :", len(attrs), "attributs proposes ; aucune ecriture dans une plateforme")
