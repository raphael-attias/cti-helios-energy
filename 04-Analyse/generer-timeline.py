#!/usr/bin/env python3
"""Génère la chronologie de présentation de l'incident INC-2026-0302, sans rien ressaisir à la main :
 - 04-Analyse/Timeline-incident.md : frise (mermaid), tableau des 12 événements observés avec technique ATT&CK, hôte, preuve et confiance,
   anomalies de chronologie, puis les 22 autres repères de Chronologie.csv (déclarés, fondés sur les IoC) ;
 - 10-Soutenance/Resume-prez-doc.md : insère le tableau condensé entre les repères <!-- TIMELINE:DEBUT --> et <!-- TIMELINE:FIN -->.
Sources : Chronologie.csv (34 événements), Matrice-analyse-alertes.csv (12 alertes, hôte, techniques), Matrice-ATTACK.csv (statut observée ou probable).
Aucune connexion réseau. Exécuter : python3 04-Analyse/generer-timeline.py"""
import csv, os, re

B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rd = lambda *p: list(csv.DictReader(open(os.path.join(B, *p), encoding="utf-8")))
chr_ = rd("04-Analyse", "Chronologie.csv"); al = {r["id"]: r for r in rd("04-Analyse", "Matrice-analyse-alertes.csv")}; att = {r["technique_id"]: r for r in rd("04-Analyse", "Matrice-ATTACK.csv")}

# phase de l'attaque par alerte (lecture analytique, fondée sur la technique rattachée)
PHASE = {"ALERT-001": "Exécution", "ALERT-002": "Chargement d'outil", "ALERT-003": "Persistance", "ALERT-004": "Commande et contrôle", "ALERT-006": "Découverte",
         "ALERT-007": "Mouvement latéral", "ALERT-008": "Injection de code", "ALERT-005": "Accès aux identifiants", "ALERT-009": "Persistance (compte)",
         "ALERT-010": "Exfiltration", "ALERT-011": "Commande et contrôle (repli)", "ALERT-012": "Effacement des traces"}
# libellé court d'événement pour la frise (le détail complet reste dans Chronologie.csv)
FRISE = {"ALERT-001": "PowerShell masqué lancé par Word", "ALERT-002": "téléchargement d'un exécutable de 421 376 octets", "ALERT-003": "tâche planifiée imitant Edge",
         "ALERT-004": "connexion de balise vers 198.51.100.24", "ALERT-006": "balayage SMB et RDP du réseau interne", "ALERT-007": "ouverture RDP du compte svc-backup-temp",
         "ALERT-008": "thread distant dans explorer.exe", "ALERT-005": "accès mémoire à LSASS sur le contrôleur de domaine", "ALERT-009": "compte svc-backup-temp créé puis supprimé",
         "ALERT-010": "2,47 Go sortis en clair vers 203.0.113.28", "ALERT-011": "contact du domaine de repli", "ALERT-012": "journal Security effacé"}

def statut_tech(tid, aid):
    row = att.get(tid)
    if not row: return "non vérifiée"
    m = re.search(aid + r" (observée|probable|contestée|écartée)", row["alertes_et_statut"])
    return m.group(1) if m else "voir matrice"

ev = []  # un événement observé = une ligne CHR dont le statut cite l'alerte
for aid, a in al.items():
    c = next(r for r in chr_ if f"({aid})" in r["statut"] or f"{aid})" in r["statut"])
    techs = [t.strip().split(" ")[0] for t in a["technique_ATTACK_proposee"].split(";")]
    ev.append(dict(aid=aid, chr=c["id"], t=c["heure_normalisee_UTC"], host=a["hote"], phase=PHASE[aid], obs=c["observation"], conf=c["niveau_de_confiance"].split(" (")[0],
                   techs=[(t, att[t]["nom_officiel"].split(": ")[-1] if t in att else "", statut_tech(t, aid)) for t in techs], preuve=c["artefact_et_ligne"].split(" ; ")[0], frise=FRISE[aid]))
ev.sort(key=lambda e: e["t"])
fmt = lambda t: t[5:10].replace("-", "/")[3:] + "/03 " + t[11:16] if False else f"{t[8:10]}/03 {t[11:16]}"
tech_cell = lambda e: " ; ".join(f"{t} {n} ({s})" if n else f"{t} ({s})" for t, n, s in e["techs"])
link = lambda e: f"[{e['chr']}](Chronologie.csv)"

# ---------- tableau condensé (résumé) ----------
def table(prefix):
    L = ["| # | Date et heure (UTC) | Phase | Hôte | Ce qui est observé | Technique ATT&CK | Confiance | Preuve |", "|---|---|---|---|---|---|---|---|"]
    for i, e in enumerate(ev, 1):
        L.append(f"| {i} | {fmt(e['t'])} | {e['phase']} | `{e['host']}` | {e['frise'][0].upper() + e['frise'][1:]} | {tech_cell(e)} | {e['conf']} | [{e['aid']}]({prefix}04-Analyse/Matrice-analyse-alertes.csv) |")
    return "\n".join(L)

# ---------- frise mermaid ----------
jours = {}
for e in ev: jours.setdefault(e["t"][8:10], []).append(e)
M = ["```mermaid", "timeline", "    title Intrusion INC-2026-0302 (heures UTC, bornes d'observation)"]
for j, es in sorted(jours.items()):
    M.append(f"    {int(j)} mars : " + " : ".join(f"{e['t'][11:16]} {e['frise']}" for e in es))
M.append("```")
FR = "\n".join(M)

ANOM = [r for r in chr_ if "ANOMALIE" in r["statut"] or r["id"] == "CHR-028"]
autres = [r for r in chr_ if not any(f"{a})" in r["statut"] for a in al) and r not in ANOM]

doc = f"""# Chronologie de l'incident INC-2026-0302

Générée par `04-Analyse/generer-timeline.py` depuis [Chronologie.csv](Chronologie.csv) (34 événements), [Matrice-analyse-alertes.csv](Matrice-analyse-alertes.csv) et [Matrice-ATTACK.csv](Matrice-ATTACK.csv). Rien n'est ressaisi à la main. **Les dates sont des bornes d'observation (du 2 au 7 mars 2026), pas le début ni la fin certains de l'intrusion.** Les « premières vues » des IoC sont des dates de découverte, pas des heures d'événement.

## 1. Frise

{FR}

## 2. Les 12 événements observés

Chaque ligne s'appuie sur une alerte SIEM retrouvée dans le journal brut. La technique ATT&CK est rattachée à l'alerte (statut observée ou probable, voir [Matrice ATT&CK](Matrice-ATTACK.csv)). L'ordre est chronologique ; les numéros d'alerte ne le sont pas.

{table("../")}

Le détail de chaque événement (observation brute, interprétation, limites) est dans la ligne correspondante de [Chronologie.csv](Chronologie.csv) : """ + ", ".join(link(e) for e in ev) + f""" pour les 12 lignes ci-dessus.

## 3. Anomalies de la chronologie (signalées, jamais corrigées)

| Repère | Constat |
|---|---|
""" + "\n".join(f"| {r['id']} ({r['heure_normalisee_UTC'][8:10]}/03 {r['heure_normalisee_UTC'][11:16]}) | {r['observation']} : {r['interpretation'][:230]} |" for r in ANOM) + f"""
| ALERT-005 | l'alerte 5 (accès LSASS, 05/03) porte un numéro plus bas que les alertes du 3 et 4 mars : la numérotation du SIEM n'est pas chronologique |

## 4. Les {len(autres)} autres repères de Chronologie.csv

Ce sont des **premières vues d'IoC déclarées** par le SOC (confiance faible) et des points de contexte : ils situent l'infrastructure mais ne sont pas des événements observés dans un journal.

| Repère | Date et heure (UTC) | Constat | Statut | Confiance |
|---|---|---|---|---|
""" + "\n".join(f"| {r['id']} | {r['heure_normalisee_UTC'][8:10]}/03 {r['heure_normalisee_UTC'][11:16]} | {r['observation']} | {r['statut'].split(' (')[0]} | {r['niveau_de_confiance'].split(' (')[0]} |" for r in autres) + """

## 5. Où retrouver chaque élément

[Chronologie.csv](Chronologie.csv) (34 lignes, 7 colonnes, référence artefact:ligne) · [Analyse des alertes](Analyse-alertes.md) · [Matrice ATT&CK](Matrice-ATTACK.csv) · [Diamond Model](Diamond-Model.md) · [Hypothèses et attribution](Hypotheses-et-attribution.md) · [Rapport tactique §4](../08-Rapports/Rapport-tactique.md) · [Journal brut](../fourniture/05_journaux_bruts.log) · [Résumé de présentation](../10-Soutenance/Resume-prez-doc.md)
"""
open(os.path.join(B, "04-Analyse", "Timeline-incident.md"), "w", encoding="utf-8").write(doc)

# ---------- insertion dans le résumé de présentation ----------
p = os.path.join(B, "10-Soutenance", "Resume-prez-doc.md"); t = open(p, encoding="utf-8").read()
bloc = f"""<!-- TIMELINE:DEBUT (généré par 04-Analyse/generer-timeline.py : ne pas modifier à la main) -->
## Chronologie de l'incident

Du 2 au 7 mars 2026 (bornes d'observation, pas début ni fin certains). Heures UTC. Chaque ligne repose sur une alerte retrouvée dans le journal brut.

{FR}

{table("../")}

**Lecture** : entrée par un document Office qui lance PowerShell masqué sur le poste de la comptabilité (2 mars), puis balayage interne (3 mars), rebond RDP et injection sur un serveur (4 mars), accès aux identifiants et sortie de 2,47 Go depuis le contrôleur de domaine (5 mars), canal de repli (6 mars), effacement du journal de sécurité (7 mars). Le compte `svc-backup-temp` est utilisé 36 heures avant sa création : anomalie signalée, non résolue.

**Détail complet** : [Chronologie de présentation, avec anomalies et repères déclarés](../04-Analyse/Timeline-incident.md) · [Chronologie.csv (34 événements)](../04-Analyse/Chronologie.csv) · [Matrice ATT&CK](../04-Analyse/Matrice-ATTACK.csv) · [Analyse des alertes](../04-Analyse/Analyse-alertes.md)
<!-- TIMELINE:FIN -->
"""
if "<!-- TIMELINE:DEBUT" in t:
    t = re.sub(r"<!-- TIMELINE:DEBUT.*?<!-- TIMELINE:FIN -->\n", lambda m: bloc, t, flags=re.S)
else:
    anchor = "---\n\n# A. Points à valider"
    assert anchor in t, "ancre introuvable"
    t = t.replace(anchor, bloc + "\n" + anchor, 1)
open(p, "w", encoding="utf-8").write(t)
print(f"timeline : {len(ev)} événements observés, {len(ANOM)} anomalies, {len(autres)} autres repères ; Timeline-incident.md et résumé mis à jour")
