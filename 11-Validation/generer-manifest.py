#!/usr/bin/env python3
"""Manifeste des livrables : chemin relatif, format, taille, sha256, date de modification, statut de validation (issu de Matrice-exigences.csv). Aucune connexion réseau."""
import csv, hashlib, os, datetime
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
mx = {r["id"]: r["statut"] for r in csv.DictReader(open(os.path.join(B, "00-Pilotage", "Matrice-exigences.csv"), encoding="utf-8"))}
MAP = [("02-Artefacts/Inventaire-IoC", "REQ-01"), ("02-Artefacts/Inventaire-alertes", "REQ-02"), ("02-Artefacts/Inventaire-binaires", "REQ-03"), ("04-Analyse/Analyse-binaires", "REQ-04"), ("02-Artefacts/Integrite", "REQ-05"),
 ("03-Sources/", "REQ-06"), ("01-Cadrage/Note-cadrage", "REQ-07"), ("01-Cadrage/Planning", "REQ-08"), ("01-Cadrage/Roles", "REQ-09"), ("04-Analyse/Analyse-", "REQ-10"), ("04-Analyse/Matrice-analyse", "REQ-10"),
 ("04-Analyse/Chronologie", "REQ-11"), ("05-Plateformes/Journal-ingestion", "REQ-13"), ("05-Plateformes/Evenement-MISP", "REQ-13"), ("05-Plateformes/Verification-MISP", "REQ-14"), ("06-STIX-Graphe/Rapport-validation", "REQ-16"),
 ("06-STIX-Graphe/Graphe", "REQ-24"), ("06-STIX-Graphe/Script-generation", "REQ-24"), ("06-STIX-Graphe/generer-graphe", "REQ-24"), ("06-STIX-Graphe/", "REQ-15"), ("04-Analyse/Matrice-ATTACK", "REQ-17"), ("04-Analyse/Diamond", "REQ-18"),
 ("04-Analyse/Hypotheses", "REQ-19"), ("04-Analyse/Indication", "REQ-19"), ("04-Analyse/Matrice-risques", "REQ-20"), ("04-Analyse/Cartographie", "REQ-21"), ("07-Detection-Tests/sigma", "REQ-22"), ("07-Detection-Tests/Registre", "REQ-22"),
 ("07-Detection-Tests/wazuh", "OPT-03"), ("07-Detection-Tests/Resultats-wazuh", "OPT-03"), ("07-Detection-Tests/", "REQ-23"), ("08-Rapports/Rapport-strategique", "REQ-25"), ("08-Rapports/Rapport-tactique", "REQ-26"), ("08-Rapports/composer", "REQ-26"),
 ("08-Rapports/Note-attribution", "REQ-27"), ("08-Rapports/Note-reglementaire", "REQ-28"), ("08-Rapports/Note-partage", "REQ-29"), ("09-Journal-mission/", "REQ-30"), ("10-Soutenance/", "REQ-31"), ("11-Validation/Couverture", "REQ-32"),
 ("11-Validation/Manifest", "REQ-33"), ("11-Validation/generer-manifest", "REQ-33"), ("11-Validation/Controle", "REQ-34"), ("11-Validation/controle", "REQ-34"), ("00-Pilotage/", "REQ-35"), ("05-Plateformes/", "SUP-01")]
rows = []
for root, dirs, files in os.walk(B):
    dirs[:] = [d for d in dirs if not d.startswith(".")]
    for f in sorted(files):
        p = os.path.join(root, f); rel = os.path.relpath(p, B)
        if rel in ("11-Validation/Manifest-livrables.csv", "11-Validation/Depot-Git-manifeste.csv"): continue  # le manifeste d'inclusion Git liste l'empreinte de celui-ci : l'inclure créerait une dépendance circulaire
        req = "source fournie (lecture seule)" if rel.startswith("fourniture/") else next((r for pre, r in MAP if rel.startswith(pre)), "support")
        st = "original fourni, inchangé" if rel.startswith("fourniture/") else (f"{req} : {mx[req]}" if req in mx else "support non évalué séparément")
        if f.endswith(".bak"): st = "sauvegarde d'une version antérieure (conservée par prudence)"
        rows.append([rel, os.path.splitext(f)[1].lstrip(".") or "texte", os.path.getsize(p), hashlib.sha256(open(p, "rb").read()).hexdigest(),
                     datetime.datetime.fromtimestamp(os.path.getmtime(p), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%MZ"), st])
with open(os.path.join(B, "11-Validation", "Manifest-livrables.csv"), "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["chemin_relatif", "format", "taille_octets", "sha256", "date_modification_utc", "statut_de_validation"]); w.writerows(rows)
print(len(rows), "fichiers listés ; le manifeste ne contient pas son propre hash")
