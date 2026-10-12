#!/usr/bin/env python3
"""Génère 00-Pilotage/Suivi-RFI.md : tableau de suivi des 5 RFI et de l'investigation. Lit les définitions dans 05-Plateformes/octi_investigation_rfi.py
et, si elle existe, la relecture réelle 05-Plateformes/Relecture-investigation-rfi.json (écrite après création). Sans elle : tout est « non créée »."""
import json, os, re
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = open(os.path.join(B, "05-Plateformes", "octi_investigation_rfi.py"), encoding="utf-8").read()
src = src.replace("__IDS__", json.dumps(json.load(open(os.path.join(B, "05-Plateformes", "IDs-OpenCTI.json"))))).replace("TOKEN = token()", "TOKEN = ''").split('if __name__')[0]
ns = {}; exec(compile(src, "octi_inv_rfi", "exec"), ns)
RF = ns["RFIS"]; R = {}
rp = os.path.join(B, "05-Plateformes", "Relecture-investigation-rfi.json")
if os.path.exists(rp): R = json.load(open(rp, encoding="utf-8"))
BASE = "http://172.16.0.4:8180/dashboard"
t = "# Suivi des RFI et de l'investigation OpenCTI\n\nGénéré par `11-Validation/generer-suivi-rfi.py`. " + ("Relecture réelle : `05-Plateformes/Relecture-investigation-rfi.json`.\n\n" if R else "**Rien n'est créé à ce jour** : les liens et identifiants n'existent pas encore.\n\n")
t += "Règles : aucun destinataire, assigné, participant, délai, réponse, approbation ni statut clos n'est inventé ; une RFI sans réponse reste ouverte (statut NEW du flux) ; une RFI créée prouve un suivi, pas l'obtention de l'information ; aucune demande n'est transmise à l'extérieur.\n\n"
t += "| Référence | Nature | Priorité (justification) | Gravité | Objets liés | Statut réel | Réponse reçue | Lien |\n|---|---|---|---|---|---|---|---|\n"
why = {"RFI-01": "bloque REQ-04", "RFI-02": "qualifie 2 IoC et la chronologie", "RFI-03": "affine la qualification, ne bloque rien", "RFI-04": "améliore l'attribution, ne bloque rien", "RFI-05": "décide de REQ-15"}
for r in RF:
    x = R.get(r["key"]); st = (x["status"]["template"]["name"] if x else "non créée"); link = f"{BASE}/cases/rfis/{x['id']}" if x else "-"
    t += f"| {r['key']} | {'investigation' if r['kind']=='investigation' else 'validation pédagogique'} | {r['priority']} ({why[r['key']]}) | {r['severity']} | {len(r['links'])} | {st} | non | {link} |\n"
inv = R.get("investigation")
t += f"\nInvestigation : `{ns['INV_NAME']}` : " + (f"{inv['investigated_entities']} identifiants enregistrés (56 entités et 30 relations existantes), identifiant `{inv['id']}`, {BASE}/workspaces/investigations/{inv['id']}\n" if inv else "non créée (56 entités prévues).\n")
t += "\nRFI-05 : le texte de la plateforme a été mis à jour le 2026-10-07 après approbation (`05-Plateformes/octi_rfi05_maj.py`) pour refléter les comptages après les ajouts STIX ; statut, priorité, liens et marquage inchangés.\n"
t += "\n## Ce qui n'est pas une RFI (décisions d'exploitation de votre SOC, non transformées en demande)\n\nMaintien ou retrait des objets de test (Q26), filtre du connecteur MISP (Q28), niveau TLP commun (Q29), marquage des 3 organisations (Q30), `valid_from` des indicateurs (Q32), sort de la règle Wazuh de production (B-19) : voir `Options-restes-production.md`. Ce sont vos décisions, pas des demandes d'information au commanditaire.\n"
open(os.path.join(B, "00-Pilotage", "Suivi-RFI.md"), "w", encoding="utf-8").write(t); print("Suivi-RFI.md :", len(RF), "RFI")
