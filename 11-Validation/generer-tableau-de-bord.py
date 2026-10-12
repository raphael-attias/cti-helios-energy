#!/usr/bin/env python3
"""Génère 00-Pilotage/Tableau-de-bord.md depuis Matrice-exigences.csv (compteurs calculés par script, jamais saisis)."""
import csv, collections, os, json
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rows = list(csv.DictReader(open(os.path.join(B, "00-Pilotage", "Matrice-exigences.csv"), encoding="utf-8")))
off = [r for r in rows if r["categorie"].startswith("officielle")]; sup = [r for r in rows if r["categorie"].startswith("demande")]; opt = [r for r in rows if r["categorie"] == "optionnelle"]
SAT, PAR, NSAT, NAP = "SATISFAIT ET CONTRÔLÉ", "PARTIEL", "NON SATISFAIT", "NON APPLICABLE"
def c(sub): return collections.Counter(r["statut"] for r in sub)
co = c(off); n = len(off); nv = co[SAT]
lv = lambda col: collections.Counter(r[col] for r in off)
def line(col, name): x = lv(col); return f"| {name} | {x['oui']} | {x['partiel']} | {x['non']} |"
def lim(i): return next(r["manque_ou_limite"] for r in rows if r["id"] == i)
t = f"""# Tableau de bord

Clôture du 2026-10-07. Compteurs **calculés par script** (`11-Validation/generer-tableau-de-bord.py`) sur `Matrice-exigences.csv`. **La mission n'est pas validée à 100 %.** Détail et preuves : `11-Validation/Cloture-finale-mission.md` et `11-Validation/Audit-final-criteres.md` ; origine des exigences : `00-Pilotage/Exigences-origine.md` ; limites et arbitrages : `00-Pilotage/Decisions-et-limites-finales.md`.

## Trois périmètres, trois couvertures (jamais mélangés)

| Périmètre | Total | {SAT} | {PAR} | {NSAT} | {NAP} | Couverture |
|---|---|---|---|---|---|---|
| **Exigences officielles** (lecture du brief ; liste non confirmée par le commanditaire) | {n} | {nv} | {co[PAR]} | {co[NSAT]} | {co[NAP]} | **{nv} / {n} ({100*nv/n:.1f} %)** |
| **Volet Wazuh optionnel** (OPT-03) | 1 | {sum(1 for r in opt if r['id']=='OPT-03' and r['statut']==SAT)} | 0 | 0 | 0 | hors dénominateur |
| **Autres optionnels** (OPT-01, 02, 04, 05) | 4 | {sum(1 for r in opt if r['id']!='OPT-03' and r['statut']==SAT)} | {sum(1 for r in opt if r['id']!='OPT-03' and r['statut']==PAR)} | 0 | {sum(1 for r in opt if r['statut']==NAP)} | hors dénominateur |
| **Demandes supplémentaires OpenCTI** (consultation, investigation, RFI) | {len(sup)} | {c(sup)[SAT]} | {c(sup)[PAR]} | {c(sup)[NSAT]} | 0 | {c(sup)[SAT]} / {len(sup)} |

**Sens des statuts** : {SAT} = livrable existant, contenu présent, preuve traçable, contrôle exécuté, limites écrites. {PAR} = livré avec une limite précise qui empêche de conclure au satisfait. {NSAT} = non livrable, avec sa cause. {NAP} = hors sujet, avec sa justification. **Aucun statut n'est une validation par le commanditaire** : celle-ci vaut **0 / {n}**. Aucun « partiel » n'a été converti en « satisfait » pour atteindre un pourcentage.

## Quatre niveaux distincts ({n} exigences officielles)

| Niveau | Oui | Partiel | Non |
|---|---|---|---|
{line('declare_realise', 'Déclaré réalisé')}
{line('preuve_archivee', 'Preuve archivée')}
{line('controle_execute_niveau', 'Contrôle exécuté (niveau déclaré)')}
{line('valide', 'Satisfait et contrôlé (critères ci-dessus)')}
{line('relu_par_commanditaire', 'Relu par l\'utilisateur ou validé par le commanditaire')}

## Ce qui n'est pas satisfait, avec sa cause

| Exigence | Statut | Cause et limite |
|---|---|---|
{chr(10).join(f"| {r['id']} {r['exigence'][:60]} | {r['statut']} | {r['manque_ou_limite']} |" for r in off if r['statut'] != SAT)}

## Visibilité dans les plateformes (vérifiée par API **et** dans les interfaces)

| Plateforme | Objets relus | Interface |
|---|---|---|
| MISP | événement 6 : 46 attributs, 5 objets, 8 galaxies, diffusion « organisation seulement », non publié | contrôlée (empreinte du certificat vérifiée) |
| OpenCTI | Analyses 1 (rapport de 103 objets), Événements (1 incident, 4 données observées, 4 détections), Observations (27 observables, 8 indicateurs, 4 infrastructures), 1 enquête en vue synthétique, 5 RFI | contrôlée les 2026-10-06 et 2026-10-07 : graphe de connaissance sur le rapport, enquête ouverte avec ses relations, RFI ouvertes sans réponse |
| Wazuh | 27 alertes `helios_challenge` (règles 130101 à 130115) | contrôlée : 27 résultats dans Discover |
| TheHive, Cortex | **non utilisés** | `05-Plateformes/Verification-TheHive.md`, `Verification-Cortex.md` |
"""
open(os.path.join(B, "00-Pilotage", "Tableau-de-bord.md"), "w", encoding="utf-8").write(t)
print("tableau de bord :", nv, "/", n)
