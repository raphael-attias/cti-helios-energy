#!/usr/bin/env python3
"""Produit Analyse-IoC-tableau.md (40 entrées) et ../02-Artefacts/Indicateurs-extraits.csv. Aucune connexion réseau."""
import csv, os, re
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ioc = {r["id"]: r for r in csv.DictReader(open(os.path.join(B, "02-Artefacts", "Inventaire-IoC.csv"), encoding="utf-8"))}
log = open(os.path.join(B, "fourniture", "05_journaux_bruts.log"), encoding="utf-8").read()
alerts = open(os.path.join(B, "fourniture", "03_alertes_siem_12.csv"), encoding="utf-8").read()
fiche = open(os.path.join(B, "fourniture", "01_fiches_analyse_binaires.md"), encoding="utf-8").read()
def where(v):
    w = []
    vv = v.lower()
    if vv in log.lower(): w.append("journal")
    if vv in alerts.lower().replace("[.]", "."): w.append("alerte")
    if vv in fiche.lower(): w.append("fiche")
    return "+".join(w) or "aucun"
# statut analytique et cote propre (source C par défaut ; crédibilité justifiée)
S = {}
def st(i, statut, cote, why): S[i] = (statut, cote, why)
for i in (1, 2, 3): st(i, "DECLARE (fiche BIN-01)", "C4", "fiche seule ; échantillon absent ; parent winword vs .xlsm (I-18)")
for i in (4, 5, 6): st(i, "CORROBORE en partie (taille 421376 = journal l.2)", "C3", "la taille concorde mais deux artefacts du même fournisseur ne sont pas indépendants ; le hash n'est pas recalculable")
for i in (7, 8, 9): st(i, "DECLARE (fiche BIN-03)", "C4", "fiche seule ; outil générique selon la fiche")
for i in (10, 11, 12): st(i, "DECLARE (IoC dérivé, aucune capture)", "C4", "empreinte d'un objet non fourni (mémoire, archive) ; IOC-011 rattaché à BIN-002 par le SOC sans lien technique")
st(13, "OBSERVE (URL dans journal l.2)", "C3", "domaine vu dans la requête proxy ; « jamais vu » non vérifiable")
st(14, "ALERTE SEULE (détail de l'alerte 4)", "C3", "absent du journal brut ; l'IP vue est 198.51.100.24, le lien domaine vers IP est déclaré (IOC-020)")
st(15, "DECLARE", "C4", "page d'hameçonnage ; ni courriel ni journal fournis")
st(16, "OBSERVE (journal l.11)", "C4", "requête vue le 6 mars mais « repli C2 » est une annotation ; infrastructure « vue » le 3 mars (I-11)")
st(17, "DECLARE", "C4", "domaine d'usurpation ; aucun artefact")
st(18, "DECLARE", "C5", "contexte « nom de tâche planifiée associé » incompréhensible (I-14)")
st(19, "DECLARE (résolution)", "C4", "résolution déclarée, non vérifiée, aucun journal DNS")
st(20, "OBSERVE (journal l.4)", "C3", "connexion vue ; rôle de balise = annotation ; une seule ligne")
st(21, "DECLARE", "C4", "« C2 principal » jamais vu dans un journal ; relation avec 198.51.100.24 non établie (I-12)")
st(22, "DECLARE", "C4", "repli déclaré, jamais vu dans un journal")
st(23, "DECLARE", "C4", "hébergement d'hameçonnage ; aucun artefact")
st(24, "OBSERVE (journal l.10)", "C3", "volume anormal observé ; contenu inconnu")
st(25, "OBSERVE mais NATURE INCONNUE (journal l.5)", "C5", "IP publique source d'un balayage interne : pseudonymisation (HYP-003), scanneur externe (HYP-004) ou erreur ; ne pas diffuser comme offensif")
st(26, "DECLARE ET CONTREDIT", "C5", "alerte 7 dit source interne, l'IoC dit externe (I-04)")
for i in (27,): st(i, "DECLARE", "C5", "passive DNS partagé avec « D-04 » (référence non résolue, I-13) ; non vérifiable")
st(28, "NON VERIFIABLE", "C6", "rapport public non fourni (cote D4 du SOC) ; aucune recherche externe lancée")
for i in (29,): st(i, "OBSERVE (journal l.2)", "C3", "GET 200 de 421376 octets ; contenu non vu")
for i in (30, 31, 32): st(i, "DECLARE", "C4", "URL du dossier ; aucun artefact d'observation")
for i in (33, 34): st(i, "DECLARE", "C4", "empreinte de certificat ; aucun certificat ni journal TLS fourni ; « partagé par les C2 » non étayé")
st(35, "NON VERIFIABLE", "C6", "pivot vers une campagne de janvier 2026 non fournie (cote C4 du SOC)")
st(36, "OBSERVE (journal l.3)", "B3", "création de tâche vue ; action et compte inconnus ; libellé Sysmon non standard (I-20)")
st(37, "OBSERVE ET CONTRADICTOIRE (journal l.6 et l.9)", "C4", "compte utilisé 36 h avant sa création (I-03)")
st(38, "DECLARE (valeur tronquée)", "C5", "« HKCU\\...\\Run\\WinTelemetry » : valeur incomplète dans la source")
st(39, "DECLARE", "C4", "fichier temporaire ; aucun artefact")
st(40, "OBSERVE (hôte dans les journaux)", "B2", "actif victime, pas un indicateur offensif")
rows = []
for n in range(1, 41):
    r = ioc[f"IOC-{n:03d}"]; sta, cote, why = S[n]
    rows.append(f"| {r['id']} | {r['type']} | `{r['valeur_normalisee'][:44]}{'…' if len(r['valeur_normalisee'])>44 else ''}` | {where(r['valeur_normalisee'])} | {r['admiralty_fournie_SOC']} | **{cote}** | {sta} | {why} |")
# cotes Admiralty de l'équipe, une ligne par IoC (fiabilité A-F séparée de la crédibilité 1-6) : source unique reprise par MISP et par le bundle STIX
with open(os.path.join(B, "02-Artefacts", "Cotes-Admiralty-IoC.csv"), "w", encoding="utf-8", newline="") as fh:
    w = csv.writer(fh); w.writerow(["id", "type", "valeur_normalisee", "cote_SOC", "cote_equipe", "fiabilite_source", "credibilite_information", "statut_analytique", "justification"])
    for n in range(1, 41):
        r = ioc[f"IOC-{n:03d}"]; sta, cote, why = S[n]
        assert re.fullmatch(r"[A-F][1-6]", cote), cote
        w.writerow([r["id"], r["type"], r["valeur_normalisee"], r["admiralty_fournie_SOC"], cote, cote[0], cote[1], sta, why])
open(os.path.join(B, "04-Analyse", "Analyse-IoC-tableau.md"), "w", encoding="utf-8").write(
    "| ID | Type | Valeur (normalisée) | Présent dans | Cote SOC | Cote équipe | Statut analytique | Justification |\n|---|---|---|---|---|---|---|---|\n" + "\n".join(rows) + "\n")
# indicateurs extraits pendant l'analyse
ext = [
 ("EXT-001", "url", "https://static-assets-cache.test/", "journal l.11 (alerte 11)", "OBSERVE", "URL complète du « repli C2 », absente des 40 IoC"),
 ("EXT-002", "cidr", "10.20.0.0/16", "journal l.5 (alerte 6) ; bruit du journal (adresses 10.20.x.x)", "OBSERVE", "réseau interne ciblé par le balayage ; plan d'adressage interne présumé"),
 ("EXT-003", "port", "8080/tcp", "journal l.10", "OBSERVE", "port de sortie de l'exfiltration, en clair selon la source"),
 ("EXT-004", "port", "443/tcp", "journal l.4", "OBSERVE", "port de la connexion de balise"),
 ("EXT-005", "ports", "445,3389", "journal l.5", "OBSERVE", "ports balayés"),
 ("EXT-006", "bytes", "2469135790", "journal l.10", "OBSERVE", "volume de la sortie (2,47 Go décimal, 2,30 Gio)"),
 ("EXT-007", "process", "winword.exe -> powershell.exe -enc ... -w hidden", "journal l.1", "OBSERVE", "chaîne de processus, commande tronquée"),
 ("EXT-008", "process", "explorer.exe (cible d'un CreateRemoteThread)", "journal l.7", "OBSERVE", "injection, initiateur inconnu"),
 ("EXT-009", "process", "lsass.exe (accès 0x1010 par rundll32_helper.dll)", "journal l.8", "OBSERVE", "lecture mémoire"),
 ("EXT-010", "process", "wevtutil cl Security", "journal l.12", "OBSERVE", "effacement de journal"),
 ("EXT-011", "command", "schtasks /create /tn MicrosoftEdgeUpdateTaskMachine", "détail de l'alerte 3 (absent du journal)", "ALERTE SEULE", "ligne de commande non reprise dans le journal brut (I-20)"),
 ("EXT-012", "base64", "SQBFAFgA = IEX (UTF-16LE)", "journal l.1", "OBSERVE (décodage reproduit)", "préfixe de la commande encodée"),
 ("EXT-013", "event_id", "4624 type 10 ; 4720 ; 4726 ; 1102", "journal l.6, 9, 12", "OBSERVE", "événements Windows Security cités"),
 ("EXT-014", "account", "m.durand, s.leroy, j.moreau, a.petit, admin.sys", "bruit du journal (sessions)", "OBSERVE (bruit)", "comptes du bruit ; aucun lien avec l'attaque démontré"),
 ("EXT-015", "mask", "0x1010", "journal l.8", "OBSERVE", "PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ"),
]
with open(os.path.join(B, "02-Artefacts", "Indicateurs-extraits.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["id", "type", "valeur", "source_et_ligne", "statut", "remarque"]); w.writerows(ext)
print(len(rows), "lignes ;", len(ext), "indicateurs extraits")
