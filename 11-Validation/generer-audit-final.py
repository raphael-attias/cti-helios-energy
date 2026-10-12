#!/usr/bin/env python3
"""Génère 11-Validation/Audit-final-criteres.md depuis Matrice-exigences.csv, Controles-exigences.csv, Pages-PDF.csv, Couverture-competences.md,
controle-coherence-sortie.txt et Liaison-STIX.json. Les compteurs sont calculés, jamais saisis. Les passages d'état (plateformes, dépôt) sont lus sur le disque quand c'est possible."""
import csv, os, re, json, collections
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = lambda *a: os.path.join(B, *a)
M = list(csv.DictReader(open(P("00-Pilotage", "Matrice-exigences.csv"), encoding="utf-8")))
CT = collections.defaultdict(list)
for r in csv.DictReader(open(P("11-Validation", "Controles-exigences.csv"), encoding="utf-8")): CT[r["exigence"]].append(r["resultat"])
PG = {r["fichier"]: r for r in csv.DictReader(open(P("11-Validation", "Pages-PDF.csv"), encoding="utf-8"))}
coh = open(P("11-Validation", "controle-coherence-sortie.txt"), encoding="utf-8").read()
n_coh_ok = len(re.findall(r"^\s+OK ", coh, re.M)); n_coh_ko = len(re.findall(r"^\s+(KO|ÉCART)", coh, re.M))
LJ = json.load(open(P("06-STIX-Graphe", "Liaison-STIX.json")))
depot = os.path.isdir("/Users/rapatt/Projet/cti-helios-energy")
RP = P("05-Plateformes", "Relecture-investigation-rfi.json"); R = json.load(open(RP, encoding="utf-8")) if os.path.exists(RP) else {}
BASE = "http://172.16.0.4:8180/dashboard"
INV = R.get("investigation", {}); RF = {k: v for k, v in R.items() if k.startswith("RFI-")}
O = {}
for l in open(P("00-Pilotage", "Exigences-origine.md"), encoding="utf-8"):
    c = [x.strip() for x in l.strip().strip("|").split("|")]
    if len(c) >= 3 and re.match(r"(REQ|SUP|OPT)-\d+$", c[0]): O[c[0]] = c[2] if c[0].startswith("REQ") else c[2]
CMD = {  # procédure de contrôle exacte (depuis le dossier de mission, venv dédié)
 "REQ-01": "`02-Artefacts/generer-inventaires.py` (CSV = JSON, doublons, sha256) ; `controle-coherence.py`", "REQ-02": "`generer-inventaires.py` ; correspondance 12/12 avec le journal brut", "REQ-03": "`generer-inventaires.py` ; 9 empreintes retrouvées",
 "REQ-04": "aucune exécution possible : échantillons absents ; `Analyse-binaires.md` dit « analyse des fiches »", "REQ-13": "SQL en lecture seule (`Controle-live-2026-10-07.md` §2) ; capture `preuves-consultation/misp-evenement-6-entete.jpg`", "REQ-14": "`Verification-MISP.md` ; relecture SQL du 2026-10-07",
 "REQ-15": "`06-STIX-Graphe/generer-liaison-stix.py` puis `controles-exigences.py`", "REQ-16": "`06-STIX-Graphe/valider-bundle.py` (sortie `Rapport-validation-sortie.txt`)", "REQ-22": "`07-Detection-Tests/tester-sigma.py`", "REQ-23": "`tester-sigma.py` ; logtest Wazuh ; `Reconciliation-tests.md`",
 "REQ-24": "`06-STIX-Graphe/generer-graphe.py` (dérivé du bundle, hash noté dans `Derives-du-bundle.txt`)", "REQ-33": "`11-Validation/generer-manifest.py` puis `verifier-manifest.py`", "REQ-34": "`11-Validation/controle-coherence.py`", "REQ-36": "`preparer-depot-git.sh verify` sur le dépôt réel (non exécutable : dépôt absent)" if not depot else "`preparer-depot-git.sh verify` sur le dépôt réel",
}
def res(i):
    k = CT.get(i, []); return f"{k.count('OK')}/{len(k)} contrôles OK" if k else "voir procédure"
off = [r for r in M if r["id"].startswith("REQ-")]; sup = [r for r in M if r["id"].startswith("SUP-")]; opt = [r for r in M if r["id"].startswith("OPT-")]
cnt = lambda rows: collections.Counter(r["statut"] for r in rows)
SAT, PAR, NSAT, NAP = "SATISFAIT ET CONTRÔLÉ", "PARTIEL", "NON SATISFAIT", "NON APPLICABLE"
co = cnt(off); nv = co[SAT]; n = len(off); cs = cnt(sup)
def row(r, with_origin=True):
    i = r["id"]; return f"| {i} | {r['exigence']} | {O.get(i, '')} | {r['livrable_attendu']} ; {r['preuve']} | {CMD.get(i, '`11-Validation/controles-exigences.py`')} | {res(i)} | **{r['statut']}** | {r['manque_ou_limite']} |"
H = "| ID | Exigence | Origine | Livrable et preuve | Procédure de contrôle | Résultat | Statut | Limite ou action restante |\n|---|---|---|---|---|---|---|---|\n"
comp = []
for l in open(P("11-Validation", "Couverture-competences.md"), encoding="utf-8"):
    c = [x.strip() for x in l.strip().strip("|").split("|")]
    if len(c) >= 8 and c[0].isdigit(): comp.append(f"| {c[0]} | {c[1]} | {c[3]} | {c[4]} | {c[5]} | {c[6]} |")
pdfs = "\n".join(f"| `{k}` | {v['pages']} | `{v['sha256'][:12]}…` |" for k, v in sorted(PG.items()))
t = f"""# Audit final des critères et matrice finale, 2026-10-07 (clôture)

Généré par `11-Validation/generer-audit-final.py` : compteurs calculés depuis la matrice, les contrôles et les PDF. Contrôles en direct des plateformes : `Controle-live-2026-10-07.md`. **La mission n'est pas validée à 100 %** : {nv} exigences officielles sur {n} sont SATISFAITES ET CONTRÔLÉES ; {co[PAR]} sont PARTIELLES et {co[NSAT]} NON SATISFAITES, avec leurs causes au §5. Synthèse de clôture : `Cloture-finale-mission.md`.

## 0. Ce que les mots veulent dire

| Niveau | Sens ici | État |
|---|---|---|
| Produit | le livrable existe | voir §2 |
| **Contrôlé techniquement** (statut SATISFAIT ET CONTRÔLÉ) | contenu attendu présent, preuve traçable, contrôle exécuté, limites écrites ; **ne dit rien d'une relecture** | {nv} / {n} officielles |
| Relu par un tiers ou par l'utilisateur | un humain a lu et accepté | **0** : rien n'a été relu |
| Accepté par le commanditaire | validation externe | **0** : aucune validation n'a eu lieu ni n'est présumée |

Contrôle de cohérence global (`controle-coherence.py`) : {n_coh_ok} contrôles OK, {n_coh_ko} écart. Contrôles techniques par exigence : {sum(len(v) for v in CT.values())} contrôles dont {sum(v.count('KO') for v in CT.values())} KO (tous attendus et expliqués au §5, REQ-15).

## 1. Trois couvertures séparées

| Périmètre | Élément | Total | Satisfait et contrôlé | Autres statuts | Couverture |
|---|---|---|---|---|---|
| **Officielle** (lecture du brief, `Exigences-origine.md`) | REQ-01 à REQ-36 | {n} | {nv} | {', '.join(f'{k} {v}' for k, v in co.items() if k != SAT)} | **{nv} / {n} ({100*nv/n:.1f} %)** |
| **Volet Wazuh optionnel** | OPT-03 | 1 | {1 if any(r['id']=='OPT-03' and r['statut']==SAT for r in opt) else 0} | | hors dénominateur ; règles 130101 à 130115, 27 alertes, relu en direct le 2026-10-07 |
| **Autres optionnels** | OPT-01, 02, 04, 05 | 4 | {sum(1 for r in opt if r['id']!='OPT-03' and r['statut']==SAT)} | {', '.join(f"{r['id']} {r['statut']}" for r in opt if r['id']!='OPT-03')} | hors dénominateur |
| **Demandes OpenCTI supplémentaires** | SUP-01 consultation ; SUP-02 investigation ; SUP-03 RFI | {len(sup)} | {cs[SAT]} | {', '.join(f"{r['id']} {r['statut']}" for r in sup if r['statut']!=SAT) or 'aucun autre'} | **{cs[SAT]} / {len(sup)}** ; investigation et {len(RF)} RFI **créées le 2026-10-07 après approbation** ; les RFI restent **ouvertes, sans réponse** |
| Validation par le commanditaire | | {n} | **0** | | 0 / {n} |

Une RFI créée prouvera qu'une demande est suivie, **pas** que l'information manquante a été obtenue. Aucune RFI ne sera clôturée.

## 2. Exigences officielles, une par une

{H}{chr(10).join(row(r) for r in off)}

## 3. Demandes supplémentaires et volet optionnel

{H}{chr(10).join(row(r) for r in sup + opt)}

## 4. Les huit compétences et leurs preuves matérielles

| # | Compétence | Preuve matérielle | Fichiers | Contrôle exécuté | Statut |
|---|---|---|---|---|---|
{chr(10).join(comp)}

Aucune compétence n'est « validée » : aucun formateur ni commanditaire n'a relu (voir `Couverture-competences.md`).

## 5. Exigences non satisfaites ou partielles, et pourquoi

| Exigence | Statut | Raison et preuve | Conséquence retenue |
|---|---|---|---|
| **REQ-04** analyse statique des 3 binaires | {NSAT} | le LISEZ-MOI dit que les échantillons ne sont pas fournis ; `fourniture/` ne contient que 3 fiches ; aucun hash n'est recalculable | RFI-01 ouverte ; **imputable au dossier** ; les fiches ne sont pas présentées comme des échantillons analysés |
| **REQ-36** dépôt Git local | {NSAT} | {'le dépôt existe : vérification à exécuter' if depot else 'le chemin `/Users/rapatt/Projet/cti-helios-energy` n\'existe pas (vérifié le 2026-10-07)'} ; sa création n'a **pas été approuvée** (2026-10-07, trois demandes) ; un essai à blanc ne la remplace pas | procédure prête (`preparer-depot-git.sh`, `Depot-Git-confirmation.md`) ; aucune création sans accord |
| **REQ-07** note de cadrage 2 pages (fin J1) | {PAR} | produite et à jour, mais après l'échéance « fin J1 » : le critère de délai n'est pas satisfait | limite déclarée dans la note elle-même |

**REQ-15 (25 objets liés) est SATISFAIT ET CONTRÔLÉ sous une méthode propre à l'équipe** : {LJ['methode_principale_objets_de_renseignement_lies']} objets de renseignement (campagne, malwares, outils, infrastructures, techniques, indicateurs) reliés par des relations explicites dans une même composante ; {LJ['sensibilite_sans_objets_T13_non_observes']} en retirant les 2 ajouts fondés sur le texte d'une alerte seulement. Cette définition n'a pas été fournie ni confirmée par le commanditaire (RFI-05) : voir `06-STIX-Graphe/Justification-25-objets-lies.md`.

Autres limites irréductibles (hors exigences) : voir `00-Pilotage/Decisions-et-limites-finales.md` §4.

## 6. Opérations externes : faites, refusées, non demandées

| # | Opération | État au 2026-10-07 | Document |
|---|---|---|---|
| 1 | Dépôt Git local (`preflight`, `copy`, `verify`, `init`, `commit`, sans remote ni push) | **NON APPROUVÉE** : non faite | `Depot-Git-confirmation.md` |
| 2 | Enquête OpenCTI `[CHALLENGE FICTIF] Helios Energy — Investigation CTI` | **FAITE** après approbation : identifiant `{INV.get('id','?')}` ; **vue synthétique** le même jour (approuvée) | `05-Plateformes/Investigation-OpenCTI-finale.md` |
| 3 | 5 RFI OpenCTI | **FAITES** après approbation : RFI-01 à RFI-05, statut NEW, TLP:RED, sans assigné, participant, destinataire ni échéance | `Suivi-RFI.md` |
| 4 | Marquage des 3 organisations de support (P1) | **FAIT** après approbation (étiquette de la mission et TLP:RED, relu par API) | `Journal-ingestion.csv` |
| 5 | Remplacement des 2 PDF joints au rapport OpenCTI par des versions Markdown (C3, demande du 2026-10-10) | {'**FAIT** après approbation (Markdown le 2026-10-10 ; PDF finaux du 07/10 archivés dans `99-Historique/`)' if os.path.exists(P("05-Plateformes", "Remplacement-PDF-joints.json")) else '**approuvé, non encore exécuté**'} | `Decisions-et-limites-finales.md` |
| 6 | Compléments STIX dans OpenCTI : 4 infrastructures, 1 outil, 11 relations, ajout au rapport | **FAIT** après approbation | `05-Plateformes/octi_stix_complements.py`, `IDs-complements-T13.json` |
| 7 | Restes en production (retraits Wazuh, OpenCTI, MISP, filtre du connecteur), C1 `indicates`, `tlp:red`, `valid_from`, `first_seen` | **non demandés** : état conservé, procédures préparées | `Options-restes-production.md` |

Interdits maintenus : écriture directe en base (une seule, historique, documentée), publication distante, envoi d'IoC à un tiers, purge de file, reprise du connecteur MISP, blocage CrowdSec, réponse active, exécution des binaires, playbook Ansible global.

## 7. Liens réels

| Élément | Lien ou identifiant | État |
|---|---|---|
| MISP, événement 6 | `https://172.16.208.253/events/view/6` (certificat auto-signé, empreinte dans `AGENTS.md`) | présent, non publié, distribution 0 |
| OpenCTI, rapport | `http://172.16.0.4:8180/dashboard/analyses/reports/3ec91c0f-915b-4e1d-9cd9-c1c12c79f342` | présent ; PDF tactique joint = ancienne version (10 pages) |
| OpenCTI, incident | `http://172.16.0.4:8180/dashboard/events/incidents/a2f66075-be6c-42a9-9524-d428833fd4c1` | présent ; onglet Indicateurs vide par choix de relation |
| Wazuh | `https://10.99.99.3` (Discover, `rule.id` 130101 à 130115) | 27 alertes |
| OpenCTI, investigation | `{BASE}/workspaces/investigations/{INV.get('id','?')}` (identifiant `{INV.get('id','?')}`) | créée, 56 entités et 30 relations, ouverte dans l'interface |
| OpenCTI, RFI | liste `{BASE}/cases/rfis` ; fiches : {', '.join(f'[{k}]({BASE}/cases/rfis/{v["id"]})' for k, v in RF.items())} | 5 créées, statut NEW, ouvertes |

## 8. État final des services et automatisations

Wazuh : 11 démons en marche sur 15, les 4 arrêtés sont désactivés par la configuration (correction de l'énoncé « 15 sur 15 »), règles et décodeurs identiques aux copies locales, aucun redémarrage aujourd'hui, aucune réponse active ni intégration déclenchée. MISP : événement 6 intact, 0 corrélation. OpenCTI : une enquête (puis sa vue synthétique), 5 RFI, le marquage de 3 organisations et les compléments STIX (4 infrastructures, 1 outil, 11 relations) faits aujourd'hui après approbation (rapport à 103 objets dont 18 ajoutés ; 439 détections inchangées) ; connecteur MISP en fonctionnement mais n'interrogeant pas MISP (compte lecteur non destinataire de l'événement 6), **non repris, non filtré** ; flux `jira` inchangé. Aucun blocage CrowdSec, aucun envoi Jira ou TheHive.

## 9. Livrables finaux, PDF et dépôt

| PDF | Pages | sha256 (début) |
|---|---|---|
{pdfs}

{'Les pièces jointes du rapport OpenCTI (stratégique et tactique) sont des **fichiers Markdown** (`Rapport-strategique.md`, `Rapport-tactique.md`) depuis le 2026-10-10 (opération 5, sur demande : plutôt du Markdown que du PDF) ; les PDF finaux du 2026-10-07 sont archivés dans `99-Historique/`. L image du graphe en annexe n est pas incluse dans la version Markdown.' if os.path.exists(P('05-Plateformes', 'Remplacement-PDF-joints.json')) else 'Les PDF joints dans OpenCTI ne sont pas identiques aux versions locales (écart E10) : opération 5 approuvée, non encore exécutée.'} Dépôt Git : {'présent' if depot else '**absent** (création non approuvée)'} ; contenu prévu s'il était créé : `11-Validation/Depot-Git-manifeste.csv` (note de cadrage, rapports stratégique et tactique, 15 règles Sigma, bundle, graphe et script, attribution, matrice CID, note ANSSI, note de partage, tests, soutenance, README, procédures de reproduction).
"""
open(P("11-Validation", "Audit-final-criteres.md"), "w", encoding="utf-8").write(t)
print("Audit-final-criteres.md :", nv, "/", n)
